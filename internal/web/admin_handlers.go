package web

import (
	"errors"
	"log"
	"net/http"
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

func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	entries, err := s.store.ListAudit(300)
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.render(w, r, "admin_audit", "Audit log", "audit", entries)
}

// ---- Machines administration ------------------------------------------------

type adminMachineView struct {
	M             *store.Machine
	EndpointNames []string
	SelectedIDs   map[int64]bool
	Online        bool
	LastHandshake time.Time
	ApprovedAt    time.Time
}

// userGroup gathers one user's machines for the admin view.
type userGroup struct {
	UID      string
	Name     string // display name (cn), falls back to uid
	Machines []adminMachineView
	Total    int
	OnlineN  int
	PendingN int
}

func (s *Server) handleAdminMachines(w http.ResponseWriter, r *http.Request) {
	machines, err := s.store.ListMachines()
	if err != nil {
		s.serverError(w, err)
		return
	}
	endpoints, err := s.store.ListEndpoints()
	if err != nil {
		s.serverError(w, err)
		return
	}

	views := make([]adminMachineView, 0, len(machines))
	for _, m := range machines {
		ids, err := s.store.EndpointIDsForMachine(m.ID)
		if err != nil {
			s.serverError(w, err)
			return
		}
		selected := make(map[int64]bool, len(ids))
		var names []string
		for _, id := range ids {
			selected[id] = true
		}
		for _, e := range endpoints {
			if selected[e.ID] {
				names = append(names, e.Name)
			}
		}
		mv := adminMachineView{M: m, EndpointNames: names, SelectedIDs: selected}
		if m.ApprovedAt != nil {
			mv.ApprovedAt = *m.ApprovedAt
		}

		peers, err := s.store.PeersByKey(m.PublicKey)
		if err != nil {
			s.serverError(w, err)
			return
		}
		for _, p := range peers {
			if p.LastHandshake.After(mv.LastHandshake) {
				mv.LastHandshake = p.LastHandshake
			}
		}
		mv.Online = online(mv.LastHandshake)
		views = append(views, mv)
	}

	used, err := s.store.UsedAddresses()
	if err != nil {
		s.serverError(w, err)
		return
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
		if mv.M.Status == store.StatusPending {
			g.PendingN++
		}
	}
	sort.Strings(order)

	groups := make([]*userGroup, 0, len(order))
	totalPending := 0
	for _, uid := range order {
		g := byUID[uid]
		sort.SliceStable(g.Machines, func(i, j int) bool {
			a, b := g.Machines[i], g.Machines[j]
			ap, bp := a.M.Status == store.StatusPending, b.M.Status == store.StatusPending
			if ap != bp {
				return ap
			}
			return a.M.Name < b.M.Name
		})
		totalPending += g.PendingN
		groups = append(groups, g)
	}

	s.render(w, r, "admin_machines", "Machines", "machines", struct {
		Groups       []*userGroup
		AllEndpoints []*store.Endpoint
		SuggestedIP  string
		TotalPending int
	}{groups, endpoints, suggested, totalPending})
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
	used, err := s.store.UsedAddresses()
	if err != nil {
		s.serverError(w, err)
		return
	}
	if err := s.pool.Validate(address, used); err != nil {
		redirectMsg(w, r, "/admin/machines", "err", err.Error())
		return
	}

	m := &store.Machine{OwnerUID: owner, Name: name, PublicKey: pubKey}
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

// handleUpdateMachine edits a machine (name, public key, address, endpoints)
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

	if err := s.store.UpdateMachineIdentity(id, name, pubKey); err != nil {
		redirectMsg(w, r, "/admin/machines", "err", "Could not save (public key already used?)")
		return
	}
	if err := s.store.ApproveMachine(id, address, endpointIDs, sessionFrom(r).UID); err != nil {
		s.serverError(w, err)
		return
	}
	s.audit(r, "machine.update", m.OwnerUID+"/"+name)
	redirectMsg(w, r, "/admin/machines", "ok", "Machine "+name+" saved ("+address+")")
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
	return e, nil
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
