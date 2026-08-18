package web

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wgroster/wgroster/internal/store"
	"github.com/wgroster/wgroster/internal/wg"
)

// machineView decorates a machine with its endpoints and live status.
type machineView struct {
	M             *store.Machine
	Endpoints     []*store.Endpoint
	Online        bool
	LastHandshake time.Time
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	machines, err := s.store.ListMachinesByOwner(sess.UID)
	if err != nil {
		s.serverError(w, err)
		return
	}
	// This page auto-refreshes every 20s, so it is built with a fixed number of
	// queries: the endpoint links and last handshakes of the user's machines are
	// fetched in one query each instead of two queries per machine.
	links, err := s.store.EndpointLinks(sess.UID)
	if err != nil {
		s.serverError(w, err)
		return
	}
	handshakes, err := s.store.LastHandshakeByKey(sess.UID)
	if err != nil {
		s.serverError(w, err)
		return
	}
	endpoints, err := s.store.ListEndpoints()
	if err != nil {
		s.serverError(w, err)
		return
	}
	views := make([]machineView, 0, len(machines))
	for _, m := range machines {
		mv := machineView{M: m, LastHandshake: handshakes[m.PublicKey]}
		mv.Online = online(mv.LastHandshake)
		linked := make(map[int64]bool, len(links[m.ID]))
		for _, id := range links[m.ID] {
			linked[id] = true
		}
		// endpoints is ordered by name, so filtering it keeps that order.
		for _, e := range endpoints {
			if linked[e.ID] {
				mv.Endpoints = append(mv.Endpoints, e)
			}
		}
		views = append(views, mv)
	}
	s.render(w, r, "dashboard", "My machines", "dashboard", views)
}

func (s *Server) handleAddMachine(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	name := strings.TrimSpace(r.FormValue("name"))
	pubKey := strings.TrimSpace(r.FormValue("public_key"))

	if !validName(name) {
		redirectMsg(w, r, "/", "err", "Machine name is required and must not contain control characters")
		return
	}
	if !validPublicKey(pubKey) {
		redirectMsg(w, r, "/", "err", "Invalid WireGuard public key")
		return
	}

	m := &store.Machine{OwnerUID: sess.UID, OwnerName: sess.Name, Name: name, PublicKey: pubKey}
	if err := s.store.CreateMachine(m); err != nil {
		// Most likely a duplicate public key.
		redirectMsg(w, r, "/", "err", "Could not add machine (key already used?)")
		return
	}
	redirectMsg(w, r, "/", "ok", "Machine added — waiting for administrator approval")
}

func (s *Server) handleMachineConfig(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
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
	if m.OwnerUID != sess.UID && !sess.Admin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if m.Status != store.StatusActive {
		redirectMsg(w, r, "/", "err", "This machine is not approved yet")
		return
	}

	eps, err := s.store.EndpointsForMachine(m.ID)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if len(eps) == 0 {
		redirectMsg(w, r, "/", "err", "This machine has no endpoint assigned — ask an administrator")
		return
	}
	conf := wg.ClientConfig(m, eps)

	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+safeFilename(m.Name)+".conf\"")
		w.Write([]byte(conf))
		return
	}

	s.render(w, r, "machine_config", "Configuration — "+m.Name, "dashboard", struct {
		Machine *store.Machine
		Config  string
	}{m, conf})
}

// handleEditMachine lets a user edit their own machine's name and public key.
// Address and endpoints stay admin-controlled and are never touched here.
// Changing the public key sends the machine back to pending (admin re-approval).
func (s *Server) handleEditMachine(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
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
	if m.OwnerUID != sess.UID && !sess.Admin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	pubKey := strings.TrimSpace(r.FormValue("public_key"))
	if !validName(name) {
		redirectMsg(w, r, "/", "err", "Machine name is required and must not contain control characters")
		return
	}
	if !validPublicKey(pubKey) {
		redirectMsg(w, r, "/", "err", "Invalid WireGuard public key")
		return
	}

	keyChanged := pubKey != m.PublicKey
	if err := s.store.UpdateMachineIdentity(id, name, pubKey); err != nil {
		redirectMsg(w, r, "/", "err", "Could not save (public key already used?)")
		return
	}
	if keyChanged && m.Status == store.StatusActive {
		if err := s.store.SetMachinePending(id); err != nil {
			s.serverError(w, err)
			return
		}
		s.audit(r, "machine.key_change", m.OwnerUID+"/"+name)
		redirectMsg(w, r, "/", "ok", "Public key changed — waiting for administrator re-approval")
		return
	}
	redirectMsg(w, r, "/", "ok", "Machine updated")
}

func (s *Server) handleDeleteMachine(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
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
	if m.OwnerUID != sess.UID && !sess.Admin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.store.DeleteMachine(id); err != nil {
		s.serverError(w, err)
		return
	}
	redirectMsg(w, r, "/", "ok", "Machine deleted")
}

func redirectMsg(w http.ResponseWriter, r *http.Request, path, key, msg string) {
	http.Redirect(w, r, path+"?"+key+"="+url.QueryEscape(msg), http.StatusSeeOther)
}

func safeFilename(name string) string {
	var b strings.Builder
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			b.WriteRune(c)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "wg"
	}
	return b.String()
}
