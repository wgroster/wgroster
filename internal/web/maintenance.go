package web

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/wgroster/wgroster/internal/config"
	"github.com/wgroster/wgroster/internal/ldap"
	"github.com/wgroster/wgroster/internal/store"
)

// orphanCheckInterval is how long a directory presence answer is trusted before
// an owner is asked about again. The sweep itself runs hourly, so this keeps
// the offboarding check to roughly one LDAP query per owner per day — and makes
// one "miss" worth one day, which is what orphan_grace_days counts.
const orphanCheckInterval = 24 * time.Hour

// RunMaintenance periodically expires stale pending machines (freeing their
// reserved IP), prunes the audit log and runs the directory offboarding and
// dormancy checks.
// No-op unless at least one of them is configured. Cancel ctx to stop.
func (s *Server) RunMaintenance(ctx context.Context) {
	if s.cfg.PendingExpiryDays <= 0 && s.cfg.AuditRetentionDays <= 0 &&
		!s.cfg.OrphanCheckEnabled() && !s.cfg.DormantCheckEnabled() {
		return
	}
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		s.sweep(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// sweep runs one round of retention: expired pending machines, old audit
// entries, then the offboarding and dormancy checks. Each step is independent
// and skipped when not configured.
func (s *Server) sweep(ctx context.Context) {
	if days := s.cfg.PendingExpiryDays; days > 0 {
		cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
		if n, err := s.store.DeleteExpiredPending(cutoff); err != nil {
			log.Printf("pending expiry: %v", err)
		} else if n > 0 {
			log.Printf("pending expiry: removed %d expired pending machine(s)", n)
		}
	}
	if days := s.cfg.AuditRetentionDays; days > 0 {
		cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
		if n, err := s.store.DeleteAuditBefore(cutoff); err != nil {
			log.Printf("audit retention: %v", err)
		} else if n > 0 {
			log.Printf("audit retention: removed %d audit entr(ies)", n)
		}
	}
	s.sweepOrphans(ctx)
	s.sweepDormant(ctx)
}

// sweepOrphans asks the directory whether every machine owner still exists, and
// acts on those that have been absent for the whole grace period.
//
// The portal is the source of truth for who gets a config, so an account that
// disappears from the directory must not leave a working peer behind. The risk
// runs the other way too — a directory that answers "absent" for everyone would
// disable the whole fleet — so absence is only ever acted upon after
// orphan_grace_days consecutive daily answers, and never at all unless the same
// round confirmed at least one other owner as present.
func (s *Server) sweepOrphans(ctx context.Context) {
	if !s.cfg.OrphanCheckEnabled() {
		return
	}
	owners, err := s.store.MachineOwnerUIDs()
	if err != nil {
		log.Printf("orphan check: %v", err)
		return
	}
	if len(owners) == 0 {
		return
	}
	checks, err := s.store.OwnerChecks()
	if err != nil {
		log.Printf("orphan check: %v", err)
		return
	}

	// 1. Refresh the owners whose last answer has aged out. Recording what the
	// directory said is always safe; only the acting phase below can change a
	// machine, so an unknown answer simply leaves the counters where they were.
	now := time.Now()
	for _, uid := range owners {
		if c, ok := checks[uid]; ok && now.Sub(c.CheckedAt) < orphanCheckInterval {
			continue
		}
		state, err := s.auth.LookupPresence(uid)
		switch state {
		case ldap.PresencePresent:
			if err := s.store.MarkOwnerPresent(uid, now); err != nil {
				log.Printf("orphan check: mark %q present: %v", uid, err)
				continue
			}
			checks[uid] = store.OwnerCheck{UID: uid, CheckedAt: now}
		case ldap.PresenceAbsent:
			c, err := s.store.MarkOwnerAbsent(uid, now)
			if err != nil {
				log.Printf("orphan check: mark %q absent: %v", uid, err)
				continue
			}
			checks[uid] = c
		default:
			// The directory could not be asked. Not evidence of anything.
			log.Printf("orphan check: %q unresolved: %v", uid, err)
		}
	}

	// 2. Decide who is out of grace, and whether the answers can be trusted.
	orphans, refusal := orphanDecision(owners, checks, s.cfg.OrphanGraceDays)
	if refusal != "" {
		log.Printf("orphan check: %s", refusal)
		return
	}
	if len(orphans) == 0 {
		return
	}

	// 3. Act, once per owner.
	for _, uid := range orphans {
		if checks[uid].Orphaned() {
			continue // already acted on in an earlier sweep
		}
		s.orphanOwner(ctx, uid, now)
	}

	if n, err := s.store.PruneOwnerChecks(); err != nil {
		log.Printf("orphan check: prune: %v", err)
	} else if n > 0 {
		log.Printf("orphan check: pruned %d stale owner record(s)", n)
	}
}

// orphanDecision picks the owners whose grace period has expired, and refuses
// the whole round when the answers look more like a broken directory than a
// wave of departures. It returns either the owners to act on, or a non-empty
// reason to do nothing.
//
// The two refusals are deliberately blunt, because the failure they guard
// against (a revoked search account, a changed bind_dn_pattern, a directory
// that stopped allowing anonymous reads) makes every user look gone at once,
// and the cost of acting on that is disconnecting the fleet:
//
//   - nobody confirmed present: the directory answered "absent" for every owner
//     it was asked about, which is not a credible fleet state;
//   - a majority absent: same smell, short of unanimity.
//
// A portal with a single owner therefore never flags: there is no second owner
// to confirm the directory is answering correctly, and guessing wrong there
// would take out its only user.
func orphanDecision(owners []string, checks map[string]store.OwnerCheck, graceDays int) (orphans []string, refusal string) {
	confirmedPresent := 0
	for _, uid := range owners {
		c, ok := checks[uid]
		if !ok {
			continue
		}
		switch {
		case c.Misses >= graceDays:
			orphans = append(orphans, uid)
		case c.Misses == 0 && !c.CheckedAt.IsZero():
			confirmedPresent++
		}
	}
	if len(orphans) == 0 {
		return nil, ""
	}
	if confirmedPresent == 0 {
		return nil, fmt.Sprintf("%d owner(s) look absent but not one was confirmed present — "+
			"refusing to act; check ldap.bind_dn_pattern, the search account and anonymous read access",
			len(orphans))
	}
	if len(orphans)*2 > len(owners) {
		return nil, fmt.Sprintf("%d of %d owner(s) look absent — refusing to act on a majority; "+
			"check the directory configuration", len(orphans), len(owners))
	}
	return orphans, ""
}

// orphanOwner applies the configured action to one offboarded owner and records
// it. The owner is only marked as flagged once every intended change succeeded,
// so a failed write is retried on the next sweep instead of being lost.
func (s *Server) orphanOwner(ctx context.Context, uid string, now time.Time) {
	machines, err := s.store.ListMachinesByOwner(uid)
	if err != nil {
		log.Printf("orphan check: machines of %q: %v", uid, err)
		return
	}

	active := 0
	disabled := 0
	for _, m := range machines {
		if m.Status != store.StatusActive {
			continue
		}
		active++
		if s.cfg.OrphanAction != config.OrphanDisable {
			continue
		}
		if err := s.store.SetMachineDisabled(m.ID); err != nil {
			log.Printf("orphan check: disable machine %d of %q: %v", m.ID, uid, err)
			continue
		}
		disabled++
		s.systemAudit("machine.orphan_disabled", fmt.Sprintf("%s (%s)", m.Name, uid))
	}
	if s.cfg.OrphanAction == config.OrphanDisable && disabled != active {
		// Some machines are still active: leave the owner unflagged so the next
		// sweep retries, and do not announce a disable that only half happened.
		return
	}

	if err := s.store.FlagOwnerOrphaned(uid, now); err != nil {
		log.Printf("orphan check: flag %q: %v", uid, err)
		return
	}

	detail := fmt.Sprintf("owner %q is no longer in the directory (%d active machine(s))", uid, active)
	if disabled > 0 {
		detail = fmt.Sprintf("owner %q is no longer in the directory (%d machine(s) disabled)", uid, disabled)
	}
	log.Printf("orphan check: %s", detail)
	s.systemAudit("owner.orphaned", uid)
	s.postAlert(ctx, alertKey{typ: "orphan", user: uid}, "firing", detail)
}

// dormantEvidenceWindow is how recent a status report must be for the dormancy
// check to trust what it knows. The bundled agent pushes every 30s, so an hour
// is a wide margin: it only rules out judging a fleet nobody is reporting on.
const dormantEvidenceWindow = time.Hour

// sweepDormant reports — and, with dormant_action: disable, takes out of service
// — the machines that have not handshaked for dormant_days.
//
// A device that stopped being used keeps a working peer forever otherwise, which
// is the longest-lived hole a VPN roster can carry. The evidence comes from the
// concentrators' own reports, so unlike the offboarding check it needs no
// directory; but for the same reason it must refuse to act when the reports
// cannot be trusted (see dormantDecision).
func (s *Server) sweepDormant(ctx context.Context) {
	if !s.cfg.DormantCheckEnabled() {
		return
	}
	machines, err := s.store.ListMachines()
	if err != nil {
		log.Printf("dormancy check: %v", err)
		return
	}
	now := time.Now()

	// A device seen again is no longer dormant, whatever the sweep decides
	// below: clearing the flag is always safe, so it happens first and
	// unconditionally.
	cutoff := now.Add(-time.Duration(s.cfg.DormantDays) * 24 * time.Hour)
	for _, m := range machines {
		if m.Dormant() && m.LastSeen.After(cutoff) {
			if err := s.store.ClearMachineDormant(m.ID); err != nil {
				log.Printf("dormancy check: clear %d: %v", m.ID, err)
				continue
			}
			log.Printf("dormancy check: %s (%s) was seen again", m.Name, m.OwnerUID)
			s.systemAudit("machine.dormant_cleared", m.OwnerUID+"/"+m.Name)
			s.postAlert(ctx, alertKey{typ: "dormant", machine: machineRef(m)}, "resolved", "")
		}
	}

	fresh, err := s.hasFreshReport()
	if err != nil {
		log.Printf("dormancy check: %v", err)
		return
	}
	dormant, refusal := dormantDecision(machines, cutoff, fresh)
	if refusal != "" {
		log.Printf("dormancy check: %s", refusal)
		return
	}
	for _, m := range dormant {
		s.dormantMachine(ctx, m, now)
	}
}

// hasFreshReport reports whether any endpoint has sent a status report recently
// enough for the fleet's handshake data to mean anything.
func (s *Server) hasFreshReport() (bool, error) {
	endpoints, err := s.store.ListEndpoints()
	if err != nil {
		return false, err
	}
	for _, e := range endpoints {
		last, ok, err := s.store.LastReport(e.ID)
		if err != nil {
			return false, err
		}
		if ok && time.Since(last) < dormantEvidenceWindow {
			return true, nil
		}
	}
	return false, nil
}

// dormantDecision picks the active machines that have not been seen since
// cutoff, and refuses the whole round when the silence says more about the
// portal than about the devices. It returns either the machines to act on, or a
// non-empty reason to do nothing.
//
// Both refusals guard the same failure: handshakes stop arriving for a reason
// that has nothing to do with the devices (every agent stopped, the upload token
// was rotated, the portal itself was down for a week). Acting on that would
// disconnect a working fleet.
//
//   - no fresh report at all: nobody is telling the portal what is happening, so
//     "not seen" is not evidence of anything;
//   - a majority dormant: reports are arriving but nearly everything looks idle,
//     which is the shape of an outage that has just ended, not of a fleet.
//
// A portal with a single active machine therefore never reaps it — there is no
// second machine to corroborate that the silence is real.
func dormantDecision(machines []*store.Machine, cutoff time.Time, freshReport bool) (dormant []*store.Machine, refusal string) {
	active := 0
	for _, m := range machines {
		if m.Status != store.StatusActive {
			continue
		}
		active++
		if m.Dormant() {
			continue // already acted upon
		}
		if m.SeenOrSince().Before(cutoff) {
			dormant = append(dormant, m)
		}
	}
	if len(dormant) == 0 {
		return nil, ""
	}
	if !freshReport {
		return nil, fmt.Sprintf("%d machine(s) look dormant but no endpoint has reported recently — "+
			"refusing to act; check the agents and their upload tokens", len(dormant))
	}
	if len(dormant)*2 > active {
		return nil, fmt.Sprintf("%d of %d active machine(s) look dormant — refusing to act on a majority; "+
			"check that every concentrator is reporting", len(dormant), active)
	}
	return dormant, ""
}

// dormantMachine applies the configured action to one dormant machine and
// records it. The flag is only set once the intended change succeeded, so a
// failed write is retried on the next sweep instead of being lost.
func (s *Server) dormantMachine(ctx context.Context, m *store.Machine, now time.Time) {
	action := "machine.dormant"
	if s.cfg.DormantAction == config.DormantDisable {
		if err := s.store.SetMachineDisabled(m.ID); err != nil {
			log.Printf("dormancy check: disable machine %d: %v", m.ID, err)
			return
		}
		action = "machine.dormant_disabled"
	}
	if err := s.store.FlagMachineDormant(m.ID, now); err != nil {
		log.Printf("dormancy check: flag machine %d: %v", m.ID, err)
		return
	}

	seen := "never connected"
	if !m.LastSeen.IsZero() {
		seen = "last handshake " + ago(m.LastSeen)
	}
	detail := fmt.Sprintf("machine %q of %q is dormant (%s)", m.Name, m.OwnerUID, seen)
	if s.cfg.DormantAction == config.DormantDisable {
		detail += " and has been disabled"
	}
	log.Printf("dormancy check: %s", detail)
	s.systemAudit(action, machineRef(m))
	s.postAlert(ctx, alertKey{typ: "dormant", machine: machineRef(m)}, "firing", detail)
}

// machineRef is how a machine is named in the audit log and on the webhook.
func machineRef(m *store.Machine) string { return m.OwnerUID + "/" + m.Name }

// systemAudit records an action taken by the portal itself rather than by an
// administrator, so the audit log tells the two apart.
func (s *Server) systemAudit(action, target string) {
	if err := s.store.AddAudit("system", action, target); err != nil {
		log.Printf("audit %s %q: %v", action, target, err)
	}
}

// RunSessionGC periodically purges expired server-side sessions so the table
// does not grow without bound from users who never explicitly log out. Cancel
// ctx to stop.
func (s *Server) RunSessionGC(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if n, err := s.sess.SweepExpired(); err != nil {
			log.Printf("session gc: %v", err)
		} else if n > 0 {
			log.Printf("session gc: removed %d expired session(s)", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
