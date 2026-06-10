package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/wgroster/wgroster/internal/store"
)

type enrollPeer struct {
	PublicKey           string `json:"public_key"`
	Endpoint            string `json:"endpoint"`
	AllowedIPs          string `json:"allowed_ips"`
	PersistentKeepalive int    `json:"persistent_keepalive"`
}

// enrollResponse gives the client everything to assemble a complete config
// locally (the private key it just generated never leaves the browser).
type enrollResponse struct {
	Address string     `json:"address"`
	DNS     string     `json:"dns"`
	MTU     int        `json:"mtu"`
	Peer    enrollPeer `json:"peer"`
}

// handleEnroll reserves an IP and registers a pending machine, returning the
// data needed to build the full config client-side. Self-enrollment must be
// enabled; the machine only connects once an admin approves it.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.SelfEnroll {
		http.Error(w, "self-enrollment is disabled", http.StatusForbidden)
		return
	}
	sess := sessionFrom(r)
	name := strings.TrimSpace(r.FormValue("name"))
	pubKey := strings.TrimSpace(r.FormValue("public_key"))
	if !validName(name) || !validPublicKey(pubKey) {
		http.Error(w, "invalid device name or public key", http.StatusBadRequest)
		return
	}

	ep, err := s.store.EndpointByName(s.cfg.SelfEnrollEndpoint)
	if err != nil {
		s.serverError(w, fmt.Errorf("self_enroll_endpoint %q not found: %w", s.cfg.SelfEnrollEndpoint, err))
		return
	}

	if s.cfg.MaxPendingPerUser > 0 {
		n, err := s.store.CountPendingByOwner(sess.UID)
		if err != nil {
			s.serverError(w, err)
			return
		}
		if n >= s.cfg.MaxPendingPerUser {
			http.Error(w, "too many pending devices; ask an administrator", http.StatusTooManyRequests)
			return
		}
	}

	used, err := s.store.UsedAddresses()
	if err != nil {
		s.serverError(w, err)
		return
	}
	address, err := s.pool.NextFree(used)
	if err != nil {
		http.Error(w, "no free address left in the pool", http.StatusConflict)
		return
	}

	m := &store.Machine{OwnerUID: sess.UID, OwnerName: sess.Name, Name: name, PublicKey: pubKey}
	if err := s.store.CreateMachine(m); err != nil {
		http.Error(w, "could not register (public key already used?)", http.StatusConflict)
		return
	}
	if err := s.store.SetMachineAddress(m.ID, address); err != nil {
		// A concurrent enrollment grabbed this address first (unique index). Drop
		// the just-created row so it is not left orphaned without an address.
		if delErr := s.store.DeleteMachine(m.ID); delErr != nil {
			log.Printf("enroll: cleanup orphaned machine %d: %v", m.ID, delErr)
		}
		http.Error(w, "address allocation conflict, please retry", http.StatusConflict)
		return
	}
	if err := s.store.SetMachineEndpoints(m.ID, []int64{ep.ID}); err != nil {
		s.serverError(w, err)
		return
	}
	s.audit(r, "machine.enroll", sess.UID+"/"+name)

	allowed := ep.AllowedIPs
	if allowed == "" {
		allowed = "0.0.0.0/0"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(enrollResponse{
		Address: address + "/32",
		DNS:     ep.DNS,
		MTU:     ep.MTU,
		Peer: enrollPeer{
			PublicKey:           ep.PublicKey,
			Endpoint:            ep.HostPort,
			AllowedIPs:          allowed,
			PersistentKeepalive: ep.PersistentKeepalive,
		},
	})
}
