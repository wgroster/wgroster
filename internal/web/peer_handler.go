package web

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/wgroster/wgroster/internal/geoip"
	"github.com/wgroster/wgroster/internal/store"
)

type recentSample struct {
	TS     time.Time
	RX     int64
	TX     int64
	RxRate int64
	TxRate int64
}

type peerDetail struct {
	EndpointID     int64
	EndpointName   string
	CSRF           string // the drawer is a partial: it carries its own token
	PublicKey      string
	Name           string
	Owner          string
	Address        string
	State          string
	MachineID      int64  // 0 when the public key is unknown to the portal
	Pending        bool   // the machine exists but awaits approval
	LinkedHere     bool   // the machine is linked to this endpoint
	Suggested      string // address prefilled in the adopt/link form
	SuggestedIsHub bool   // Suggested is the address the hub already announces
	Endpoints      []string
	RemoteEndpoint string
	PTR            string
	GeoEnabled     bool
	Geo            geoip.Result
	LastHandshake  time.Time
	FirstSeen      time.Time
	HasFirstSeen   bool
	RX             int64
	TX             int64
	RxRate         int64
	TxRate         int64
	HubAllowedIPs  string
	AddrMismatch   bool
	RxSpark        []int64
	TxSpark        []int64
	Recent         []recentSample
}

func (s *Server) handlePeerDetail(w http.ResponseWriter, r *http.Request) {
	endpointID, err := parseInt64(r.URL.Query().Get("endpoint"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	key := r.URL.Query().Get("key")
	ep, err := s.store.GetEndpoint(endpointID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	d := peerDetail{
		EndpointID:   ep.ID,
		EndpointName: ep.Name,
		CSRF:         sessionFrom(r).CSRF,
		PublicKey:    key,
		Name:         "(unknown)",
		GeoEnabled:   s.geo.Enabled(),
	}

	// Reported sample for this peer on this endpoint.
	peers, err := s.store.PeersForEndpoint(endpointID)
	if err != nil {
		s.serverError(w, err)
		return
	}
	var reported *store.StatusPeer
	for i := range peers {
		if peers[i].PublicKey == key {
			reported = &peers[i]
			break
		}
	}

	// Machine identity (may be absent → unknown peer).
	if m, err := s.store.MachineByPublicKey(key); err == nil {
		d.MachineID = m.ID
		d.Pending = m.Status == store.StatusPending
		d.Name = m.Name
		d.Owner = m.OwnerDisplay()
		d.Address = m.Address
		if eps, err := s.store.EndpointsForMachine(m.ID); err == nil {
			for _, e := range eps {
				d.Endpoints = append(d.Endpoints, e.Name)
				if e.ID == endpointID {
					d.LinkedHere = true
				}
			}
		}
		if reported == nil {
			// Nothing reported here: only meaningful for a machine the portal
			// does expect on this endpoint.
			if d.Pending || !d.LinkedHere {
				http.NotFound(w, r)
				return
			}
			d.State = statePeerMissing
		}
	} else if reported == nil {
		http.NotFound(w, r)
		return
	}

	if reported != nil {
		d.RemoteEndpoint = reported.RemoteEndpoint
		d.LastHandshake = reported.LastHandshake
		d.RX, d.TX = reported.RX, reported.TX
		d.HubAllowedIPs = reported.AllowedIPs
		switch {
		case d.MachineID == 0:
			d.State = statePeerExtra
		case d.Pending || !d.LinkedHere:
			// Reported by the hub, known to the portal, but not expected here —
			// same classification as the status table (see buildStatus).
			d.State = statePeerUnlinked
		case online(reported.LastHandshake):
			d.State = statePeerOnline
		default:
			d.State = statePeerOffline
		}
		if d.Address != "" && reported.AllowedIPs != "" {
			d.AddrMismatch = !allowedCovers(reported.AllowedIPs, d.Address)
		}

		// Reverse DNS + offline geo of the remote IP (on demand, drawer only).
		if host, _, err := net.SplitHostPort(reported.RemoteEndpoint); err == nil && host != "" {
			d.PTR = lookupPTR(r, host)
			if s.geo.Enabled() {
				d.Geo = s.geo.Lookup(host)
			}
		}
	}

	// Address prefilled in the drawer's adopt/link form.
	if d.State == statePeerExtra || d.State == statePeerUnlinked {
		d.Suggested, d.SuggestedIsHub = s.suggestAddress(d.Address, d.HubAllowedIPs)
	}

	// First seen = earliest recorded sample (within the history retention
	// window), not the oldest of the capped series below — otherwise it would
	// slide with the window and read a constant "~N min ago".
	if ts, ok, err := s.store.PeerFirstSeen(endpointID, key); err == nil && ok {
		d.FirstSeen, d.HasFirstSeen = ts, true
	}

	// History → throughput sparklines + recent samples.
	if samples, err := s.store.PeerSeries(endpointID, key, 60); err == nil && len(samples) > 0 {
		for i := 1; i < len(samples); i++ {
			dt := samples[i].TS.Unix() - samples[i-1].TS.Unix()
			if dt <= 0 {
				continue
			}
			rx := nonNeg((samples[i].RX - samples[i-1].RX) / dt)
			tx := nonNeg((samples[i].TX - samples[i-1].TX) / dt)
			d.RxSpark = append(d.RxSpark, rx)
			d.TxSpark = append(d.TxSpark, tx)
			d.Recent = append(d.Recent, recentSample{TS: samples[i].TS, RX: samples[i].RX, TX: samples[i].TX, RxRate: rx, TxRate: tx})
		}
		if n := len(d.RxSpark); n > 0 {
			d.RxRate, d.TxRate = d.RxSpark[n-1], d.TxSpark[n-1]
		}
		// Keep the recent table short, newest first.
		if len(d.Recent) > 12 {
			d.Recent = d.Recent[len(d.Recent)-12:]
		}
		for i, j := 0, len(d.Recent)-1; i < j; i, j = i+1, j-1 {
			d.Recent[i], d.Recent[j] = d.Recent[j], d.Recent[i]
		}
	}

	s.renderPartial(w, "peer_drawer", d)
}

// handleAdoptPeer registers a peer the hub reports but the portal has never seen
// as a machine, and links it to the reporting endpoint — the one-step way to
// import a WireGuard config that predates the portal. The public key is taken
// from the hub report, never from the form, so a stale drawer cannot be used to
// register an arbitrary key.
func (s *Server) handleAdoptPeer(w http.ResponseWriter, r *http.Request) {
	ep, p, ok := s.reportedPeer(w, r)
	if !ok {
		return
	}
	owner := strings.TrimSpace(r.PostFormValue("owner_uid"))
	name := strings.TrimSpace(r.PostFormValue("name"))
	address := strings.TrimSpace(r.PostFormValue("address"))

	if !validName(owner) || !validName(name) {
		redirectMsg(w, r, "/admin/status", "err", "Owner and machine name are required and must not contain control characters")
		return
	}
	// The dump parser only checks the shape loosely; hold an adopted key to the
	// same standard as one typed by an administrator.
	if !validPublicKey(p.PublicKey) {
		redirectMsg(w, r, "/admin/status", "err", "The reported public key is not a valid WireGuard key")
		return
	}
	if m, err := s.store.MachineByPublicKey(p.PublicKey); err == nil {
		redirectMsg(w, r, "/admin/status", "err", "This peer is already registered as "+m.Name)
		return
	}
	used, err := s.store.UsedAddresses()
	if err != nil {
		s.serverError(w, err)
		return
	}
	if err := s.pool.Validate(address, used); err != nil {
		redirectMsg(w, r, "/admin/status", "err", err.Error())
		return
	}

	m := &store.Machine{OwnerUID: owner, Name: name, PublicKey: p.PublicKey}
	if err := s.store.CreateMachine(m); err != nil {
		redirectMsg(w, r, "/admin/status", "err", "Could not create machine (public key already used?)")
		return
	}
	if err := s.store.ApproveMachine(m.ID, address, []int64{ep.ID}, sessionFrom(r).UID); err != nil {
		s.serverError(w, err)
		return
	}
	s.audit(r, "machine.adopt", owner+"/"+name+" on "+ep.Name)
	redirectMsg(w, r, "/admin/status", "ok", "Adopted "+name+" ("+address+") on "+ep.Name)
}

// handleLinkPeer resolves an unlinked peer: the hub reports a key the portal
// knows, but the machine is not active on that endpoint. It adds the endpoint to
// the machine's links and activates it, which also covers approving a machine
// still pending.
func (s *Server) handleLinkPeer(w http.ResponseWriter, r *http.Request) {
	ep, p, ok := s.reportedPeer(w, r)
	if !ok {
		return
	}
	m, err := s.store.MachineByPublicKey(p.PublicKey)
	if err != nil {
		redirectMsg(w, r, "/admin/status", "err", "This peer is not registered in the portal")
		return
	}

	address := strings.TrimSpace(r.PostFormValue("address"))
	used, err := s.store.UsedAddresses()
	if err != nil {
		s.serverError(w, err)
		return
	}
	// The machine may keep the address it already holds.
	used = without(used, m.Address)
	if err := s.pool.Validate(address, used); err != nil {
		redirectMsg(w, r, "/admin/status", "err", err.Error())
		return
	}

	ids, err := s.store.EndpointIDsForMachine(m.ID)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if !containsID(ids, ep.ID) {
		ids = append(ids, ep.ID)
	}
	if err := s.store.ApproveMachine(m.ID, address, ids, sessionFrom(r).UID); err != nil {
		s.serverError(w, err)
		return
	}
	s.audit(r, "machine.link", m.OwnerUID+"/"+m.Name+" on "+ep.Name)
	redirectMsg(w, r, "/admin/status", "ok", m.Name+" is now active on "+ep.Name+" ("+address+")")
}

// reportedPeer resolves the endpoint and the reported peer addressed by the
// "endpoint" and "key" form fields, writing a 404 when either is unknown. Both
// are read from the body only (like the CSRF token) so nothing sensitive travels
// in a URL. Acting solely on a peer the hub actually reported keeps these routes
// aligned with what the drawer shows.
func (s *Server) reportedPeer(w http.ResponseWriter, r *http.Request) (*store.Endpoint, *store.StatusPeer, bool) {
	endpointID, err := parseInt64(r.PostFormValue("endpoint"))
	if err != nil {
		http.NotFound(w, r)
		return nil, nil, false
	}
	ep, err := s.store.GetEndpoint(endpointID)
	if err != nil {
		http.NotFound(w, r)
		return nil, nil, false
	}
	key := r.PostFormValue("key")
	peers, err := s.store.PeersForEndpoint(endpointID)
	if err != nil {
		s.serverError(w, err)
		return nil, nil, false
	}
	for i := range peers {
		if peers[i].PublicKey == key {
			return ep, &peers[i], true
		}
	}
	http.NotFound(w, r)
	return nil, nil, false
}

// suggestAddress proposes the address prefilled in the drawer's adopt/link form.
// An address the machine already holds is kept; otherwise the address the hub
// already announces is preferred, so the concentrator needs no config change,
// and the next free address in the pool is the fallback.
func (s *Server) suggestAddress(current, hubAllowedIPs string) (addr string, isHub bool) {
	hub := hubAddress(hubAllowedIPs)
	if current != "" {
		return current, hub != "" && hub == current
	}
	used, err := s.store.UsedAddresses()
	if err != nil {
		return "", false
	}
	if hub != "" && s.pool.Validate(hub, used) == nil {
		return hub, true
	}
	next, err := s.pool.NextFree(used)
	if err != nil {
		return "", false
	}
	return next, false
}

// hubAddress returns the first address of a hub's allowed-ips list without its
// prefix length, e.g. "10.0.0.7/32, fd00::7/128" → "10.0.0.7".
func hubAddress(allowedIPs string) string {
	for _, part := range strings.Split(allowedIPs, ",") {
		part = strings.TrimSpace(part)
		if i := strings.IndexByte(part, '/'); i >= 0 {
			part = part[:i]
		}
		if a, err := netip.ParseAddr(part); err == nil {
			return a.String()
		}
	}
	return ""
}

func containsID(ids []int64, id int64) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

func nonNeg(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}

// lookupPTR does a best-effort reverse DNS lookup with a short timeout.
func lookupPTR(r *http.Request, ip string) string {
	ctx, cancel := context.WithTimeout(r.Context(), 1500*time.Millisecond)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}
