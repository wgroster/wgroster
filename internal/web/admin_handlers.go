package web

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wgroster/wgroster/internal/auth"
	"github.com/wgroster/wgroster/internal/store"
	"github.com/wgroster/wgroster/internal/wg"
)

// audit records an administrative action performed by the current session.
func (s *Server) audit(r *http.Request, action, target string) {
	actor := "?"
	if sess := sessionFrom(r); sess != nil {
		actor = sess.UID
	}
	if err := s.store.AddAudit(actor, action, target); err != nil {
		log.Printf("audit %s %q: %v", action, target, err)
	}
}

// auditLimits are the row counts offered on the audit page. The first is the
// default; anything else in ?limit= falls back to it, so the query never turns
// into an unbounded scan.
var auditLimits = []int{300, 1000, 5000}

// auditLimit maps a ?limit= value to one of auditLimits, falling back to the
// default for anything unrecognised.
func auditLimit(raw string) int {
	if v, err := strconv.Atoi(raw); err == nil {
		for _, allowed := range auditLimits {
			if v == allowed {
				return v
			}
		}
	}
	return auditLimits[0]
}

func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	limit := auditLimit(r.URL.Query().Get("limit"))
	entries, err := s.store.ListAudit(limit)
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.render(w, r, "admin_audit", "Audit log", "audit", struct {
		Entries   []store.AuditEntry
		Limit     int
		Limits    []int
		Truncated bool
	}{entries, limit, auditLimits, len(entries) == limit})
}

// ---- Machines administration ------------------------------------------------

// machineEndpoint is one endpoint a machine is linked to, named and addressable
// — the row links to the live status of each of them, not just the first.
type machineEndpoint struct {
	ID   int64
	Name string
}

type adminMachineView struct {
	M             *store.Machine
	Endpoints     []machineEndpoint
	SelectedIDs   map[int64]bool
	Online        bool
	LastHandshake time.Time
	ApprovedAt    time.Time
	// RemoteIP is the address the peer last connected from, as the hub saw it,
	// without the port. RemoteHint is what the row's tooltip spells out: the full
	// host:port, plus location and network when GeoIP is configured.
	RemoteIP   string
	RemoteHint string
	// HubStale reports that no endpoint this machine is linked to has sent a
	// recent status report, so its state here is the last one the portal was
	// told about rather than what is happening now. HubHint says which endpoint
	// went quiet and when.
	HubStale bool
	HubHint  string
	// Traffic is the peer's recent transfer on the endpoint that reported it
	// last: current rates plus a short shape for the row's sparkline.
	Traffic store.PeerTraffic
}

// userGroup gathers one user's machines for the admin view.
type userGroup struct {
	UID       string
	Name      string // display name (cn), falls back to uid
	HasPhoto  bool   // a directory photo is cached (served at /avatar/{uid})
	Machines  []adminMachineView
	Total     int
	OnlineN   int
	PendingN  int
	DisabledN int
	DormantN  int
	// Orphaned reports that the directory no longer knows this owner and the
	// grace period has expired; AbsentSince is when the first absence was seen.
	Orphaned    bool
	AbsentSince time.Time
}

// attention ranks a group by how much it is waiting on an administrator: a
// decision to take first, then something merely flagged, then nothing.
func (g *userGroup) attention() int {
	switch {
	case g.PendingN > 0 || g.Orphaned:
		return 0
	case g.DormantN > 0:
		return 1
	default:
		return 2
	}
}

// rowSparkPoints is how many report intervals the per-machine curve covers. It
// is deliberately short: the row answers "is this moving?", the drawer answers
// "how much, since when", and the query behind it scans that window for every
// peer of every endpoint on each 20s poll.
const rowSparkPoints = 24

// adminMachinesView is what both the machines page and its htmx fragment
// render. The CSRF token travels with it because the fragment has no page
// envelope.
type adminMachinesView struct {
	Groups       []*userGroup
	AllEndpoints []*store.Endpoint
	SuggestedIP  string
	TotalPending int
	CSRF         string
}

func (s *Server) handleAdminMachines(w http.ResponseWriter, r *http.Request) {
	view, err := s.buildAdminMachines(r)
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.render(w, r, "admin_machines", "Machines", "machines", view)
}

// handleAdminMachinesList serves just the machine list, which the page polls
// every 20s. Rendering the whole page for it would rebuild the create form and
// one edit dialog per machine only for htmx to keep a single div.
func (s *Server) handleAdminMachinesList(w http.ResponseWriter, r *http.Request) {
	view, err := s.buildAdminMachines(r)
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.renderPartial(w, "admin_machines_list", view)
}

func (s *Server) buildAdminMachines(r *http.Request) (adminMachinesView, error) {
	view := adminMachinesView{CSRF: sessionFrom(r).CSRF}
	machines, err := s.store.ListMachines()
	if err != nil {
		return view, err
	}
	endpoints, err := s.store.ListEndpoints()
	if err != nil {
		return view, err
	}

	// Endpoint links, live handshakes and directory profiles are fetched in one
	// query each rather than per machine: every query goes through the single
	// serialized SQLite connection, and this page lists the whole fleet.
	links, err := s.store.EndpointLinks("")
	if err != nil {
		return view, err
	}
	peers, err := s.store.LatestPeerByKey("")
	if err != nil {
		return view, err
	}
	profiles, err := s.store.AllUserProfileMetas()
	if err != nil {
		return view, err
	}
	ownerChecks, err := s.store.OwnerChecks()
	if err != nil {
		return view, err
	}

	// Whether each endpoint is still reporting. A machine's "offline" only means
	// something when the hub carrying it is talking to the portal; otherwise the
	// row would state, with the same confidence, something nobody has checked
	// since the agent stopped.
	reports := make(map[int64]endpointReport, len(endpoints))
	traffic := map[string]store.PeerTraffic{}
	for _, e := range endpoints {
		at, ok, err := s.store.LastReport(e.ID)
		if err != nil {
			return view, err
		}
		reports[e.ID] = endpointReport{at: at, has: ok, fresh: ok && time.Since(at) < onlineThreshold, name: e.Name}

		// Recent traffic for every peer of this endpoint in one go. A machine
		// carried by several endpoints keeps the busiest of them: the row has a
		// single curve, and what it should show is where the device is actually
		// talking.
		peerTraffic, err := s.store.TrafficByKey(e.ID, rowSparkPoints)
		if err != nil {
			return view, err
		}
		for k, t := range peerTraffic {
			if cur, seen := traffic[k]; !seen || t.RxRate+t.TxRate > cur.RxRate+cur.TxRate {
				traffic[k] = t
			}
		}
	}

	views := make([]adminMachineView, 0, len(machines))
	for _, m := range machines {
		ids := links[m.ID]
		selected := make(map[int64]bool, len(ids))
		for _, id := range ids {
			selected[id] = true
		}
		// endpoints is ordered by name, so filtering it keeps that order.
		var linked []machineEndpoint
		for _, e := range endpoints {
			if selected[e.ID] {
				linked = append(linked, machineEndpoint{ID: e.ID, Name: e.Name})
			}
		}
		mv := adminMachineView{M: m, Endpoints: linked, SelectedIDs: selected}
		if m.ApprovedAt != nil {
			mv.ApprovedAt = *m.ApprovedAt
		}
		peer := peers[m.PublicKey]
		mv.LastHandshake = peer.LastHandshake
		if mv.LastHandshake.IsZero() {
			// No hub currently carries this peer (removed, endpoint deleted), or it
			// never handshaked here: fall back to the last handshake the portal ever
			// recorded for it, so the row says "last seen 3 months ago" rather than
			// "never" for a device that clearly did connect once.
			mv.LastHandshake = m.LastSeen
		}
		mv.Online = online(mv.LastHandshake)
		mv.RemoteIP, mv.RemoteHint = s.remoteOrigin(peer.RemoteEndpoint)
		mv.HubStale, mv.HubHint = hubSilence(ids, reports)
		mv.Traffic = traffic[m.PublicKey]
		views = append(views, mv)
	}

	used, err := s.store.UsedAddresses()
	if err != nil {
		return view, err
	}
	suggested, _ := s.pool.NextFree(used)

	// Group machines by owner, pending ones first within each group.
	byUID := map[string]*userGroup{}
	var order []string
	for _, mv := range views {
		g := byUID[mv.M.OwnerUID]
		if g == nil {
			g = &userGroup{UID: mv.M.OwnerUID, Name: mv.M.OwnerDisplay()}
			byUID[mv.M.OwnerUID] = g
			order = append(order, mv.M.OwnerUID)
		}
		g.Machines = append(g.Machines, mv)
		g.Total++
		if mv.Online {
			g.OnlineN++
		}
		switch mv.M.Status {
		case store.StatusPending:
			g.PendingN++
		case store.StatusDisabled:
			g.DisabledN++
		}
		if mv.M.Dormant() {
			g.DormantN++
		}
	}
	sort.Strings(order)

	groups := make([]*userGroup, 0, len(order))
	totalPending := 0
	for _, uid := range order {
		g := byUID[uid]
		sort.SliceStable(g.Machines, func(i, j int) bool {
			a, b := g.Machines[i], g.Machines[j]
			ar, br := store.StatusRank(a.M.Status), store.StatusRank(b.M.Status)
			if ar != br {
				return ar < br
			}
			return a.M.Name < b.M.Name
		})
		// Enrich the group header with the cached directory profile: prefer the
		// LDAP display name over the per-machine cached name, and flag a photo so
		// the template shows the avatar instead of an initial badge.
		if p, found := profiles[uid]; found {
			if p.DisplayName != "" {
				g.Name = p.DisplayName
			}
			g.HasPhoto = p.HasPhoto
		}
		if c, found := ownerChecks[uid]; found && c.Orphaned() {
			g.Orphaned = true
			g.AbsentSince = c.AbsentSince
		}
		totalPending += g.PendingN
		groups = append(groups, g)
	}
	// Owners who need something from an administrator come first: a decision to
	// take (a machine awaiting review, an account that left the directory), then
	// a device the dormancy check flagged, then everyone else alphabetically. On
	// a page that is mostly a long alphabetical wall, what is actionable should
	// not have to be hunted for.
	sort.SliceStable(groups, func(i, j int) bool {
		return groups[i].attention() < groups[j].attention()
	})

	// Lazily refresh stale/missing profiles in the background (no-op without an
	// LDAP service account); photos and names appear on a subsequent load.
	s.refreshProfilesAsync(order, profiles)

	view.Groups, view.AllEndpoints = groups, endpoints
	view.SuggestedIP, view.TotalPending = suggested, totalPending
	return view, nil
}

// endpointReport is what the machines list knows about one endpoint's last
// status upload.
type endpointReport struct {
	at    time.Time
	has   bool
	fresh bool
	name  string
}

// hubSilence reports whether none of the endpoints a machine is linked to has
// sent a recent status report, and describes the silence for the tooltip.
//
// A machine linked to several endpoints is only unknown when every one of them
// has gone quiet: a single reporting hub is enough to know the machine is not
// connected there. A machine with no endpoint at all is not judged.
func hubSilence(ids []int64, reports map[int64]endpointReport) (bool, string) {
	if len(ids) == 0 {
		return false, ""
	}
	var quiet []string
	for _, id := range ids {
		rep, ok := reports[id]
		if !ok {
			continue
		}
		if rep.fresh {
			return false, ""
		}
		if rep.has {
			quiet = append(quiet, fmt.Sprintf("%s last reported %s", rep.name, ago(rep.at)))
		} else {
			quiet = append(quiet, rep.name+" has never reported")
		}
	}
	if len(quiet) == 0 {
		return false, ""
	}
	return true, strings.Join(quiet, ", ") +
		" — this is the last state the portal was told about, not what is happening now"
}

// remoteOrigin splits the "host:port" the hub reported into the address to show
// on a row and a fuller tooltip. Where a peer connects from is how an
// administrator recognises a device that moved, a tunnel that came up from an
// unexpected network, or two machines sharing one line; the port changes on
// every NAT rebind and is noise on the row itself, so it moves to the tooltip
// along with the offline GeoIP answer when one is configured.
func (s *Server) remoteOrigin(remote string) (ip, hint string) {
	if remote == "" {
		return "", ""
	}
	host, _, err := net.SplitHostPort(remote)
	if err != nil || host == "" {
		return "", ""
	}
	hint = remote
	if s.geo.Enabled() {
		if g := s.geo.Lookup(host); !g.Empty() {
			where := g.Country
			if g.City != "" {
				where = g.City + ", " + g.Country
			}
			if where != "" {
				hint += " · " + where
			}
			if g.ASN != "" {
				hint += " · " + g.ASN
				if g.Org != "" {
					hint += " " + g.Org
				}
			}
		}
	}
	return host, hint
}

// handleAdminCreateMachine lets an administrator register a machine and activate
// it immediately (no pending step).
func (s *Server) handleAdminCreateMachine(w http.ResponseWriter, r *http.Request) {
	owner := strings.TrimSpace(r.FormValue("owner_uid"))
	name := strings.TrimSpace(r.FormValue("name"))
	pubKey := strings.TrimSpace(r.FormValue("public_key"))
	address := strings.TrimSpace(r.FormValue("address"))
	endpointIDs := parseEndpointIDs(r.Form["endpoint_ids"])

	if !validName(owner) || !validName(name) {
		redirectMsg(w, r, "/admin/machines", "err", "Owner and machine name are required and must not contain control characters")
		return
	}
	if !validPublicKey(pubKey) {
		redirectMsg(w, r, "/admin/machines", "err", "Invalid WireGuard public key")
		return
	}
	if len(endpointIDs) == 0 {
		redirectMsg(w, r, "/admin/machines", "err", "Select at least one endpoint")
		return
	}
	conflict, err := s.allowedIPsConflict(endpointIDs)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if conflict != "" {
		redirectMsg(w, r, "/admin/machines", "err", conflict)
		return
	}
	used, err := s.store.UsedAddresses()
	if err != nil {
		s.serverError(w, err)
		return
	}
	if err := s.pool.Validate(address, used); err != nil {
		redirectMsg(w, r, "/admin/machines", "err", err.Error())
		return
	}

	m := &store.Machine{OwnerUID: owner, Name: name, PublicKey: pubKey,
		Icon: store.NormalizeIcon(r.FormValue("icon"))}
	if err := s.store.CreateMachine(m); err != nil {
		redirectMsg(w, r, "/admin/machines", "err", "Could not create machine (public key already used?)")
		return
	}
	if err := s.store.ApproveMachine(m.ID, address, endpointIDs, sessionFrom(r).UID); err != nil {
		s.serverError(w, err)
		return
	}
	s.audit(r, "machine.create", owner+"/"+name)
	redirectMsg(w, r, "/admin/machines", "ok", "Machine "+name+" created for "+owner+" ("+address+")")
}

// handleUpdateMachine edits a machine (name, icon, public key, address, endpoints)
// and activates it. Used both to approve a pending machine and to edit an
// active one.
func (s *Server) handleUpdateMachine(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	m, err := s.store.GetMachine(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	pubKey := strings.TrimSpace(r.FormValue("public_key"))
	address := strings.TrimSpace(r.FormValue("address"))
	endpointIDs := parseEndpointIDs(r.Form["endpoint_ids"])

	if !validName(name) {
		redirectMsg(w, r, "/admin/machines", "err", "Machine name is required and must not contain control characters")
		return
	}
	if !validPublicKey(pubKey) {
		redirectMsg(w, r, "/admin/machines", "err", "Invalid WireGuard public key")
		return
	}
	if len(endpointIDs) == 0 {
		redirectMsg(w, r, "/admin/machines", "err", "Select at least one endpoint")
		return
	}
	conflict, err := s.allowedIPsConflict(endpointIDs)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if conflict != "" {
		redirectMsg(w, r, "/admin/machines", "err", conflict)
		return
	}

	used, err := s.store.UsedAddresses()
	if err != nil {
		s.serverError(w, err)
		return
	}
	// Exclude this machine's current address (it may keep the same one).
	used = without(used, m.Address)
	if err := s.pool.Validate(address, used); err != nil {
		redirectMsg(w, r, "/admin/machines", "err", err.Error())
		return
	}

	if err := s.store.UpdateMachineIdentity(id, name, pubKey, r.FormValue("icon")); err != nil {
		redirectMsg(w, r, "/admin/machines", "err", "Could not save (public key already used?)")
		return
	}
	// Saving the form activates the machine — that is what approving a pending
	// one means. A disabled machine is the exception: taking it out of service
	// was a deliberate act, so an edit keeps it out until it is enabled again.
	if m.Status == store.StatusDisabled {
		if err := s.store.SetMachineAssignment(id, address, endpointIDs); err != nil {
			s.serverError(w, err)
			return
		}
		s.audit(r, "machine.update", m.OwnerUID+"/"+name)
		redirectMsg(w, r, "/admin/machines", "ok", "Machine "+name+" saved — still disabled")
		return
	}
	if err := s.store.ApproveMachine(id, address, endpointIDs, sessionFrom(r).UID); err != nil {
		s.serverError(w, err)
		return
	}
	s.audit(r, "machine.update", m.OwnerUID+"/"+name)
	redirectMsg(w, r, "/admin/machines", "ok", "Machine "+name+" saved ("+address+")")
}

// handleDisableMachine takes a machine out of service without deleting it: it
// leaves every concentrator's expected peer list on the next pull, but keeps its
// address, endpoint links and history so enabling it again is one click.
func (s *Server) handleDisableMachine(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	m, err := s.store.GetMachine(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if m.Status == store.StatusDisabled {
		redirectMsg(w, r, "/admin/machines", "ok", "Machine "+m.Name+" is already disabled")
		return
	}
	if err := s.store.SetMachineDisabled(id); err != nil {
		s.serverError(w, err)
		return
	}
	s.audit(r, "machine.disable", m.OwnerUID+"/"+m.Name)
	redirectMsg(w, r, "/admin/machines", "ok", "Machine "+m.Name+" disabled — it drops out of the expected peer list")
}

// handleEnableMachine puts a disabled machine back into service.
func (s *Server) handleEnableMachine(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	m, err := s.store.GetMachine(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if m.Status != store.StatusDisabled {
		redirectMsg(w, r, "/admin/machines", "err", "Only a disabled machine can be enabled — review a pending one instead")
		return
	}
	// A machine disabled before it was ever approved (or whose endpoint was
	// deleted meanwhile) has nothing to be activated with; say so rather than
	// producing an active machine that no concentrator can serve.
	eps, err := s.store.EndpointIDsForMachine(id)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if m.Address == "" || len(eps) == 0 {
		redirectMsg(w, r, "/admin/machines", "err", "Assign an address and at least one endpoint before enabling "+m.Name)
		return
	}
	if err := s.store.SetMachineActive(id, sessionFrom(r).UID); err != nil {
		s.serverError(w, err)
		return
	}
	s.audit(r, "machine.enable", m.OwnerUID+"/"+m.Name)
	redirectMsg(w, r, "/admin/machines", "ok", "Machine "+m.Name+" enabled")
}

func (s *Server) handleAdminDeleteMachine(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	target := strconv.FormatInt(id, 10)
	if m, err := s.store.GetMachine(id); err == nil {
		target = m.OwnerUID + "/" + m.Name
	}
	if err := s.store.DeleteMachine(id); err != nil {
		s.serverError(w, err)
		return
	}
	s.audit(r, "machine.delete", target)
	redirectMsg(w, r, "/admin/machines", "ok", "Machine deleted")
}

// ---- Endpoints administration -----------------------------------------------

type endpointAdminView struct {
	E           *store.Endpoint
	ExpectedN   int
	HasReport   bool
	ReportFresh bool
	LastReport  time.Time
	Config      string // concentrator wg0.conf (interface + all assigned peers)
}

func (s *Server) handleAdminEndpoints(w http.ResponseWriter, r *http.Request) {
	endpoints, err := s.store.ListEndpoints()
	if err != nil {
		s.serverError(w, err)
		return
	}

	views := make([]endpointAdminView, 0, len(endpoints))
	for _, e := range endpoints {
		ev := endpointAdminView{E: e}
		if ms, err := s.store.ActiveMachinesForEndpoint(e.ID); err == nil {
			ev.ExpectedN = len(ms)
			ev.Config = wg.ConcentratorConfig(e, ms)
		}
		if last, ok, err := s.store.LastReport(e.ID); err == nil && ok {
			ev.HasReport = true
			ev.LastReport = last
			ev.ReportFresh = time.Since(last) < onlineThreshold
		}
		views = append(views, ev)
	}

	s.render(w, r, "admin_endpoints", "Endpoints", "endpoints", struct {
		Endpoints []endpointAdminView
		BaseURL   string
	}{views, strings.TrimRight(s.cfg.BaseURL, "/")})
}

func (s *Server) handleCreateEndpoint(w http.ResponseWriter, r *http.Request) {
	e, err := endpointFromForm(r, &store.Endpoint{})
	if err != nil {
		redirectMsg(w, r, "/admin/endpoints", "err", err.Error())
		return
	}
	token, err := auth.RandomToken(32)
	if err != nil {
		s.serverError(w, err)
		return
	}
	e.UploadToken = token
	if err := s.store.CreateEndpoint(e); err != nil {
		redirectMsg(w, r, "/admin/endpoints", "err", "Could not create endpoint (name or public key already used?)")
		return
	}
	s.audit(r, "endpoint.create", e.Name)
	redirectMsg(w, r, "/admin/endpoints", "ok", "Endpoint "+e.Name+" created")
}

func (s *Server) handleUpdateEndpoint(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	e, err := s.store.GetEndpoint(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if _, err := endpointFromForm(r, e); err != nil {
		redirectMsg(w, r, "/admin/endpoints", "err", err.Error())
		return
	}
	// endpointFromForm edited the record in place, so e now holds the pending
	// AllowedIPs: check them against the machines that already combine this
	// endpoint with another one before they are stored.
	conflict, err := s.endpointEditConflict(e)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if conflict != "" {
		redirectMsg(w, r, "/admin/endpoints", "err", conflict)
		return
	}
	if err := s.store.UpdateEndpoint(e); err != nil {
		s.serverError(w, err)
		return
	}
	s.audit(r, "endpoint.update", e.Name)
	redirectMsg(w, r, "/admin/endpoints", "ok", "Endpoint "+e.Name+" updated")
}

// handleEndpointConfig serves the concentrator's own WireGuard configuration:
// its [Interface] section plus a [Peer] per machine currently assigned to it.
func (s *Server) handleEndpointConfig(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	e, err := s.store.GetEndpoint(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	machines, err := s.store.ActiveMachinesForEndpoint(e.ID)
	if err != nil {
		s.serverError(w, err)
		return
	}
	conf := wg.ConcentratorConfig(e, machines)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+safeFilename(e.Name)+".conf\"")
	w.Write([]byte(conf))
}

func (s *Server) handleRegenerateToken(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	token, err := auth.RandomToken(32)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if err := s.store.SetEndpointToken(id, token); err != nil {
		s.serverError(w, err)
		return
	}
	target := strconv.FormatInt(id, 10)
	if e, err := s.store.GetEndpoint(id); err == nil {
		target = e.Name
	}
	s.audit(r, "endpoint.token_regen", target)
	redirectMsg(w, r, "/admin/endpoints", "ok", "Upload token regenerated — update the concentrator")
}

func (s *Server) handleDeleteEndpoint(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	target := strconv.FormatInt(id, 10)
	if e, err := s.store.GetEndpoint(id); err == nil {
		target = e.Name
	}
	if err := s.store.DeleteEndpoint(id); err != nil {
		s.serverError(w, err)
		return
	}
	s.audit(r, "endpoint.delete", target)
	redirectMsg(w, r, "/admin/endpoints", "ok", "Endpoint deleted")
}

// endpointFromForm fills e from the submitted form, validating required fields.
func endpointFromForm(r *http.Request, e *store.Endpoint) (*store.Endpoint, error) {
	e.Name = strings.TrimSpace(r.FormValue("name"))
	e.PublicKey = strings.TrimSpace(r.FormValue("public_key"))
	e.HostPort = strings.TrimSpace(r.FormValue("host_port"))
	e.AllowedIPs = strings.TrimSpace(r.FormValue("allowed_ips"))
	e.DNS = strings.TrimSpace(r.FormValue("dns"))
	e.TunnelIP = strings.TrimSpace(r.FormValue("tunnel_ip"))
	e.MTU = atoiDefault(r.FormValue("mtu"), 0)
	e.PersistentKeepalive = atoiDefault(r.FormValue("persistent_keepalive"), 0)

	if e.Name == "" {
		return nil, errors.New("endpoint name is required")
	}
	if !validPublicKey(e.PublicKey) {
		return nil, errors.New("invalid endpoint public key")
	}
	if e.HostPort == "" {
		return nil, errors.New("endpoint host:port is required")
	}
	// These fields are emitted line-by-line into generated client configs;
	// reject control characters to prevent config injection via a stray newline.
	if hasControlChar(e.Name) || hasControlChar(e.HostPort) || hasControlChar(e.AllowedIPs) ||
		hasControlChar(e.DNS) || hasControlChar(e.TunnelIP) {
		return nil, errors.New("endpoint fields must not contain control characters")
	}
	// The portal never talks to the concentrator, so nothing else will catch a
	// malformed value: it is copied verbatim into configs that clients then
	// refuse, far from here. Check the shape while the administrator is looking.
	if err := validHostPort(e.HostPort); err != nil {
		return nil, err
	}
	if _, err := wg.ParseAllowedIPs(e.AllowedIPs); err != nil {
		return nil, fmt.Errorf("allowed IPs: %w", err)
	}
	if err := validDNSList(e.DNS); err != nil {
		return nil, fmt.Errorf("DNS: %w", err)
	}
	if e.TunnelIP != "" {
		if _, err := wg.ParseAllowedIPs(e.TunnelIP); err != nil {
			return nil, fmt.Errorf("tunnel IP: %w", err)
		}
	}
	if e.MTU != 0 && (e.MTU < 576 || e.MTU > 65535) {
		return nil, fmt.Errorf("MTU %d is out of range (576-65535, or 0 to leave it unset)", e.MTU)
	}
	if e.PersistentKeepalive < 0 || e.PersistentKeepalive > 65535 {
		return nil, fmt.Errorf("persistent keepalive %d is out of range (0-65535)", e.PersistentKeepalive)
	}
	return e, nil
}

// allowedIPsConflict reports the first pair of endpoints among the given ids
// whose AllowedIPs overlap, as a message to show the administrator.
//
// A machine linked to several endpoints gets one [Peer] per endpoint in a single
// client config, and WireGuard routes every allowed IP to exactly one of them:
// overlapping lists mean one of the tunnels silently never receives that
// traffic. Refusing the link is the only place the portal can catch it, since it
// never sees the client apply the config.
func (s *Server) allowedIPsConflict(endpointIDs []int64) (string, error) {
	return s.conflictAmong(endpointIDs, nil)
}

// conflictAmong is allowedIPsConflict with one endpoint optionally replaced by a
// version that has not been stored yet, so an edit can be refused before it
// breaks the machines already linked to it.
func (s *Server) conflictAmong(endpointIDs []int64, override *store.Endpoint) (string, error) {
	if len(endpointIDs) < 2 {
		return "", nil
	}
	type parsed struct {
		name    string
		allowed []netip.Prefix
	}
	var eps []parsed
	for _, id := range endpointIDs {
		e, err := s.store.GetEndpoint(id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return "", err
		}
		if override != nil && override.ID == id {
			e = override
		}
		allowed, err := wg.AllowedIPsOr(e.AllowedIPs)
		if err != nil {
			// Stored before this was validated: not this request's problem.
			continue
		}
		eps = append(eps, parsed{name: e.Name, allowed: allowed})
	}
	for i := range eps {
		for j := i + 1; j < len(eps); j++ {
			if a, b, ok := wg.Overlap(eps[i].allowed, eps[j].allowed); ok {
				return fmt.Sprintf("%s (%s) and %s (%s) overlap: a machine cannot use both, "+
					"WireGuard would route %s through only one of them",
					eps[i].name, a, eps[j].name, b, a), nil
			}
		}
	}
	return "", nil
}

// endpointEditConflict reports the first machine whose endpoint links would
// become contradictory if e were saved as it stands. Widening an endpoint's
// AllowedIPs is the other way a multi-site machine's config silently breaks, so
// the same rule is applied from both ends.
func (s *Server) endpointEditConflict(e *store.Endpoint) (string, error) {
	links, err := s.store.EndpointLinks("")
	if err != nil {
		return "", err
	}
	for machineID, ids := range links {
		if len(ids) < 2 || !containsID(ids, e.ID) {
			continue
		}
		conflict, err := s.conflictAmong(ids, e)
		if err != nil {
			return "", err
		}
		if conflict == "" {
			continue
		}
		name := strconv.FormatInt(machineID, 10)
		if m, err := s.store.GetMachine(machineID); err == nil {
			name = m.OwnerUID + "/" + m.Name
		}
		return fmt.Sprintf("%s is linked to both: %s", name, conflict), nil
	}
	return "", nil
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func without(slice []string, v string) []string {
	out := slice[:0:0]
	for _, s := range slice {
		if s != v {
			out = append(out, s)
		}
	}
	return out
}
