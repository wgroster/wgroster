package web

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/wgroster/wgroster/internal/config"
	"github.com/wgroster/wgroster/internal/store"
)

// checks builds an OwnerChecks-shaped map: uid -> consecutive misses. A miss
// count of 0 means the directory confirmed the user in the last round.
func checksFrom(misses map[string]int) map[string]store.OwnerCheck {
	now := time.Unix(1_700_000_000, 0)
	out := map[string]store.OwnerCheck{}
	for uid, n := range misses {
		out[uid] = store.OwnerCheck{UID: uid, Misses: n, CheckedAt: now}
	}
	return out
}

func TestOrphanDecision(t *testing.T) {
	tests := []struct {
		name    string
		owners  []string
		misses  map[string]int
		grace   int
		want    []string
		refusal string
	}{
		{
			name:   "absent for the whole grace period",
			owners: []string{"alice", "bob", "carol", "dave"},
			misses: map[string]int{"alice": 0, "bob": 0, "carol": 0, "dave": 3},
			grace:  3,
			want:   []string{"dave"},
		},
		{
			name:   "still within the grace period",
			owners: []string{"alice", "bob", "carol", "dave"},
			misses: map[string]int{"alice": 0, "bob": 0, "carol": 0, "dave": 2},
			grace:  3,
		},
		{
			// An LDAP outage leaves every owner unchecked: no absences, nothing
			// to do — and above all nothing to disable.
			name:   "directory never answered",
			owners: []string{"alice", "bob"},
			misses: map[string]int{},
			grace:  3,
		},
		{
			// The shape of a revoked service account or a changed bind DN
			// pattern: the directory answers, and denies everyone.
			name:    "nobody confirmed present",
			owners:  []string{"alice", "bob", "carol"},
			misses:  map[string]int{"alice": 5, "bob": 5, "carol": 5},
			grace:   3,
			refusal: "not one was confirmed present",
		},
		{
			name:    "majority absent",
			owners:  []string{"alice", "bob", "carol"},
			misses:  map[string]int{"alice": 0, "bob": 4, "carol": 4},
			grace:   3,
			refusal: "refusing to act on a majority",
		},
		{
			// A single-owner portal has no second owner to corroborate the
			// directory, so it deliberately never acts.
			name:    "single owner",
			owners:  []string{"alice"},
			misses:  map[string]int{"alice": 9},
			grace:   3,
			refusal: "not one was confirmed present",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, refusal := orphanDecision(tc.owners, checksFrom(tc.misses), tc.grace)
			if tc.refusal != "" {
				if !strings.Contains(refusal, tc.refusal) {
					t.Fatalf("refusal = %q, want it to mention %q", refusal, tc.refusal)
				}
				if got != nil {
					t.Errorf("orphans = %v, want none when refusing", got)
				}
				return
			}
			if refusal != "" {
				t.Fatalf("unexpected refusal: %s", refusal)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("orphans = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("orphans = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// orphanOwner with "disable" must actually drop the peer from what the
// concentrators are told to carry — that is the whole point of the check.
func TestOrphanOwnerDisableRemovesPeerFromEndpoint(t *testing.T) {
	srv, _, _, _ := testServer(t)
	srv.cfg.OrphanGraceDays = 3
	srv.cfg.OrphanAction = config.OrphanDisable

	ep := &store.Endpoint{Name: "par", PublicKey: key(9), HostPort: "vpn.example.com:51820", UploadToken: "t"}
	if err := srv.store.CreateEndpoint(ep); err != nil {
		t.Fatal(err)
	}
	m := &store.Machine{OwnerUID: "gone", Name: "laptop", PublicKey: key(1)}
	if err := srv.store.CreateMachine(m); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.ApproveMachine(m.ID, "10.0.0.5", []int64{ep.ID}, "admin"); err != nil {
		t.Fatal(err)
	}
	if peers, err := srv.store.ActiveMachinesForEndpoint(ep.ID); err != nil || len(peers) != 1 {
		t.Fatalf("before: %d peer(s), err %v, want 1", len(peers), err)
	}

	now := time.Now()
	if _, err := srv.store.MarkOwnerAbsent("gone", now); err != nil {
		t.Fatal(err)
	}
	srv.orphanOwner(context.Background(), "gone", now)

	peers, err := srv.store.ActiveMachinesForEndpoint(ep.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 0 {
		t.Errorf("after: %d peer(s) still expected on the hub, want 0", len(peers))
	}
	// The machine is kept (address and endpoint links intact) so re-enabling is
	// one click if the account comes back. It is disabled, not sent back to
	// pending: an offboarded device is not awaiting review, and pending expiry
	// would eventually delete it and release its address.
	got, err := srv.store.GetMachine(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != store.StatusDisabled {
		t.Errorf("status = %q, want %q", got.Status, store.StatusDisabled)
	}
	if n, err := srv.store.CountPendingByOwner("gone"); err != nil || n != 0 {
		t.Errorf("pending count = %d, err %v, want 0 (a disabled machine is not in the review queue)", n, err)
	}
	if n, err := srv.store.DeleteExpiredPending(time.Now().Add(time.Hour)); err != nil || n != 0 {
		t.Errorf("pending expiry deleted %d machine(s), err %v, want 0", n, err)
	}
	if got.Address != "10.0.0.5" {
		t.Errorf("address = %q, want it kept", got.Address)
	}
	if links, err := srv.store.EndpointIDsForMachine(m.ID); err != nil || len(links) != 1 {
		t.Errorf("endpoint links = %v, err %v, want them kept", links, err)
	}

	check, err := srv.store.OwnerCheck("gone")
	if err != nil {
		t.Fatal(err)
	}
	if !check.Orphaned() {
		t.Error("owner should be flagged so the action does not fire again")
	}

	entries, err := srv.store.ListAudit(50)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range entries {
		if e.Actor != "system" {
			t.Errorf("audit actor = %q, want %q for a portal-initiated action", e.Actor, "system")
		}
		actions = append(actions, e.Action)
	}
	joined := strings.Join(actions, ",")
	if !strings.Contains(joined, "owner.orphaned") || !strings.Contains(joined, "machine.orphan_disabled") {
		t.Errorf("audit actions = %v, want both the owner and the machine recorded", actions)
	}
}

// The default action reports without touching anything.
func TestOrphanOwnerFlagLeavesMachinesActive(t *testing.T) {
	srv, _, _, _ := testServer(t)
	srv.cfg.OrphanGraceDays = 3
	srv.cfg.OrphanAction = config.OrphanFlag

	m := &store.Machine{OwnerUID: "gone", Name: "laptop", PublicKey: key(1)}
	if err := srv.store.CreateMachine(m); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.ApproveMachine(m.ID, "10.0.0.5", nil, "admin"); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	if _, err := srv.store.MarkOwnerAbsent("gone", now); err != nil {
		t.Fatal(err)
	}
	srv.orphanOwner(context.Background(), "gone", now)

	got, err := srv.store.GetMachine(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != store.StatusActive {
		t.Errorf("status = %q, want the machine left %q", got.Status, store.StatusActive)
	}
	check, err := srv.store.OwnerCheck("gone")
	if err != nil {
		t.Fatal(err)
	}
	if !check.Orphaned() {
		t.Error("the owner should still be flagged so the admin page shows it")
	}
}

// sweepOrphans must stay inert unless it is both configured and backed by a
// directory it can ask.
func TestSweepOrphansDisabledByDefault(t *testing.T) {
	srv, _, _, _ := testServer(t)
	m := &store.Machine{OwnerUID: "gone", Name: "laptop", PublicKey: key(1)}
	if err := srv.store.CreateMachine(m); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.ApproveMachine(m.ID, "10.0.0.5", nil, "admin"); err != nil {
		t.Fatal(err)
	}

	// No orphan_grace_days, and no LDAP: nothing may happen.
	srv.sweepOrphans(context.Background())

	checks, err := srv.store.OwnerChecks()
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 0 {
		t.Errorf("recorded %d check(s) with the feature off, want none", len(checks))
	}
	got, err := srv.store.GetMachine(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != store.StatusActive {
		t.Errorf("status = %q, want it untouched", got.Status)
	}
}

// The admin machines page must surface an offboarded owner, so a "flag" run is
// not silent.
func TestAdminMachinesShowsOrphanedOwner(t *testing.T) {
	srv, h, cookies, _ := testServer(t)

	m := &store.Machine{OwnerUID: "gone", Name: "laptop", PublicKey: key(1)}
	if err := srv.store.CreateMachine(m); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.ApproveMachine(m.ID, "10.0.0.5", nil, "admin"); err != nil {
		t.Fatal(err)
	}

	if body := do(t, h, "GET", "/admin/machines", cookies, nil).Body.String(); strings.Contains(body, "Not in directory") {
		t.Fatal("a healthy owner must not be badged")
	}

	now := time.Now()
	if _, err := srv.store.MarkOwnerAbsent("gone", now); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.FlagOwnerOrphaned("gone", now); err != nil {
		t.Fatal(err)
	}

	w := do(t, h, "GET", "/admin/machines", cookies, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Not in directory") || !strings.Contains(body, "owner offboarded") {
		t.Error("the machines page does not show the orphaned owner")
	}
}

// machineSeen builds an active machine last seen at the given time (zero = it
// never connected, in which case approval stands in for it).
func machineSeen(name string, lastSeen, approved time.Time) *store.Machine {
	m := &store.Machine{OwnerUID: "alice", Name: name, Status: store.StatusActive,
		LastSeen: lastSeen, CreatedAt: approved}
	m.ApprovedAt = &approved
	return m
}

func TestDormantDecision(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cutoff := now.Add(-90 * 24 * time.Hour)
	old := now.Add(-200 * 24 * time.Hour)
	recent := now.Add(-time.Hour)

	tests := []struct {
		name     string
		machines []*store.Machine
		fresh    bool
		want     []string
		refusal  string
	}{
		{
			name: "one device silent among many",
			machines: []*store.Machine{
				machineSeen("a", recent, old), machineSeen("b", recent, old),
				machineSeen("c", recent, old), machineSeen("d", old, old),
			},
			fresh: true,
			want:  []string{"d"},
		},
		{
			name: "never connected, counted from approval",
			machines: []*store.Machine{
				machineSeen("a", recent, old), machineSeen("b", recent, old),
				machineSeen("c", time.Time{}, old),
			},
			fresh: true,
			want:  []string{"c"},
		},
		{
			name: "approved yesterday and never connected is not dormant yet",
			machines: []*store.Machine{
				machineSeen("a", recent, old),
				machineSeen("b", time.Time{}, now.Add(-24*time.Hour)),
			},
			fresh: true,
		},
		{
			name: "nothing reported: no evidence, no action",
			machines: []*store.Machine{
				machineSeen("a", recent, old), machineSeen("b", recent, old),
				machineSeen("c", recent, old), machineSeen("d", old, old),
			},
			fresh:   false,
			refusal: "no endpoint has reported recently",
		},
		{
			name: "a majority looks idle: an outage, not a fleet",
			machines: []*store.Machine{
				machineSeen("a", old, old), machineSeen("b", old, old), machineSeen("c", recent, old),
			},
			fresh:   true,
			refusal: "refusing to act on a majority",
		},
		{
			name:     "a single active machine is never reaped on its own",
			machines: []*store.Machine{machineSeen("a", old, old)},
			fresh:    true,
			refusal:  "refusing to act on a majority",
		},
		{
			name: "already flagged machines are not acted on twice",
			machines: []*store.Machine{
				machineSeen("a", recent, old), machineSeen("b", recent, old),
				func() *store.Machine {
					m := machineSeen("c", old, old)
					m.DormantSince = now
					return m
				}(),
			},
			fresh: true,
		},
		{
			name: "a disabled machine is out of scope",
			machines: []*store.Machine{
				machineSeen("a", recent, old), machineSeen("b", recent, old),
				func() *store.Machine {
					m := machineSeen("c", old, old)
					m.Status = store.StatusDisabled
					return m
				}(),
			},
			fresh: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, refusal := dormantDecision(tc.machines, cutoff, tc.fresh)
			if tc.refusal != "" {
				if !strings.Contains(refusal, tc.refusal) {
					t.Fatalf("refusal = %q, want it to mention %q", refusal, tc.refusal)
				}
				return
			}
			if refusal != "" {
				t.Fatalf("unexpected refusal: %s", refusal)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("dormant = %d machine(s), want %d", len(got), len(tc.want))
			}
			for i := range got {
				if got[i].Name != tc.want[i] {
					t.Fatalf("dormant[%d] = %q, want %q", i, got[i].Name, tc.want[i])
				}
			}
		})
	}
}

// The dormancy sweep must take a silent device out of what the concentrators are
// told to carry, and let it back in as soon as it is seen again.
func TestSweepDormantDisablesAndClears(t *testing.T) {
	srv, _, _, _ := testServer(t)
	srv.cfg.DormantDays = 90
	srv.cfg.DormantAction = config.DormantDisable

	ep := &store.Endpoint{Name: "par", PublicKey: key(9), HostPort: "vpn.example.com:51820", UploadToken: "t"}
	if err := srv.store.CreateEndpoint(ep); err != nil {
		t.Fatal(err)
	}
	// Three active machines: two seen just now, one silent for 200 days.
	var ids []int64
	for i, b := range []byte{1, 2, 3} {
		m := &store.Machine{OwnerUID: "alice", Name: string(rune('a' + i)), PublicKey: key(b)}
		if err := srv.store.CreateMachine(m); err != nil {
			t.Fatal(err)
		}
		if err := srv.store.ApproveMachine(m.ID, "10.0.0."+string(rune('1'+i)), []int64{ep.ID}, "admin"); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, m.ID)
	}
	now := time.Now()
	report := func(silentHandshake time.Time) {
		peers := []store.StatusPeer{
			{PublicKey: key(1), LastHandshake: now.Add(-time.Minute)},
			{PublicKey: key(2), LastHandshake: now.Add(-time.Minute)},
			{PublicKey: key(3), LastHandshake: silentHandshake},
		}
		if err := srv.store.ReplaceStatus(ep.ID, peers, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	report(now.Add(-200 * 24 * time.Hour))

	srv.sweepDormant(context.Background())

	m, err := srv.store.GetMachine(ids[2])
	if err != nil {
		t.Fatal(err)
	}
	if !m.Dormant() {
		t.Fatal("the silent machine was not flagged dormant")
	}
	if m.Status != store.StatusDisabled {
		t.Errorf("status = %q, want %q", m.Status, store.StatusDisabled)
	}
	if peers, err := srv.store.ActiveMachinesForEndpoint(ep.ID); err != nil || len(peers) != 2 {
		t.Errorf("expected peers = %d, err %v, want 2", len(peers), err)
	}
	for _, id := range ids[:2] {
		if other, err := srv.store.GetMachine(id); err != nil || other.Dormant() {
			t.Errorf("machine %d flagged dormant, err %v — it was seen a minute ago", id, err)
		}
	}
	entries, err := srv.store.ListAudit(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != "machine.dormant_disabled" || entries[0].Actor != "system" {
		t.Errorf("audit = %+v, want one system machine.dormant_disabled entry", entries)
	}

	// A second pass must not act again.
	srv.sweepDormant(context.Background())
	if entries, err := srv.store.ListAudit(50); err != nil || len(entries) != 1 {
		t.Errorf("audit after a second sweep = %d entr(ies), err %v, want 1", len(entries), err)
	}

	// The device comes back: the flag goes away (the admin still decides whether
	// to put it back into service).
	report(now.Add(-time.Minute))
	srv.sweepDormant(context.Background())
	m, err = srv.store.GetMachine(ids[2])
	if err != nil {
		t.Fatal(err)
	}
	if m.Dormant() {
		t.Error("the dormancy flag survived the device being seen again")
	}
	if m.Status != store.StatusDisabled {
		t.Errorf("status = %q, want the machine to stay disabled until an admin enables it", m.Status)
	}
}

// Without a recent status report the portal knows nothing about the fleet, and
// must not read that silence as a fleet of dormant devices.
func TestSweepDormantRefusesWithoutFreshReport(t *testing.T) {
	srv, _, _, _ := testServer(t)
	srv.cfg.DormantDays = 90
	srv.cfg.DormantAction = config.DormantDisable

	ep := &store.Endpoint{Name: "par", PublicKey: key(9), HostPort: "vpn.example.com:51820", UploadToken: "t"}
	if err := srv.store.CreateEndpoint(ep); err != nil {
		t.Fatal(err)
	}
	for i, b := range []byte{1, 2, 3} {
		m := &store.Machine{OwnerUID: "alice", Name: string(rune('a' + i)), PublicKey: key(b)}
		if err := srv.store.CreateMachine(m); err != nil {
			t.Fatal(err)
		}
		if err := srv.store.ApproveMachine(m.ID, "10.0.0."+string(rune('1'+i)), []int64{ep.ID}, "admin"); err != nil {
			t.Fatal(err)
		}
	}
	// One old report: the peers were seen long ago and nothing has arrived since.
	stale := time.Now().Add(-48 * time.Hour)
	peers := []store.StatusPeer{
		{PublicKey: key(1), LastHandshake: time.Now().Add(-time.Minute)},
		{PublicKey: key(2), LastHandshake: time.Now().Add(-time.Minute)},
		{PublicKey: key(3), LastHandshake: time.Now().Add(-200 * 24 * time.Hour)},
	}
	if err := srv.store.ReplaceStatus(ep.ID, peers, stale); err != nil {
		t.Fatal(err)
	}

	srv.sweepDormant(context.Background())

	machines, err := srv.store.ListMachines()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range machines {
		if m.Dormant() || m.Status != store.StatusActive {
			t.Errorf("machine %q acted upon (dormant=%v status=%q) without a fresh report",
				m.Name, m.Dormant(), m.Status)
		}
	}
}
