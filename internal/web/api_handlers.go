package web

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/wgroster/wgroster/internal/store"
	"github.com/wgroster/wgroster/internal/wg"
)

const maxUploadBytes = 1 << 20 // 1 MiB of "wg show dump" is plenty.

// authEndpoint resolves the endpoint from the path id and verifies the bearer
// token matches that endpoint's upload token.
func (s *Server) authEndpoint(w http.ResponseWriter, r *http.Request) (*store.Endpoint, bool) {
	id, err := pathID(r)
	if err != nil {
		http.NotFound(w, r)
		return nil, false
	}
	token := bearerToken(r)
	if token == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "missing token", http.StatusUnauthorized)
		return nil, false
	}
	e, err := s.store.GetEndpoint(id)
	if err != nil {
		http.NotFound(w, r)
		return nil, false
	}
	if subtleEqual(token, e.UploadToken) {
		return e, true
	}
	// Respond exactly as for an unknown endpoint id so a caller cannot enumerate
	// which endpoint ids exist by distinguishing 403 (exists, wrong token) from
	// 404 (does not exist).
	http.NotFound(w, r)
	return nil, false
}

func (s *Server) handleStatusUpload(w http.ResponseWriter, r *http.Request) {
	e, ok := s.authEndpoint(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxUploadBytes))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	peers := wg.ParseDump(string(body))
	for i := range peers {
		peers[i].EndpointID = e.ID
	}
	if err := s.store.ReplaceStatus(e.ID, peers, time.Now()); err != nil {
		s.serverError(w, err)
		return
	}
	// Only log anomalies; successful uploads are already in the access log.
	if len(peers) == 0 {
		if len(body) == 0 {
			log.Printf("status upload for endpoint %d (%s): empty body — nothing reported", e.ID, e.Name)
		} else {
			sample := string(body)
			if len(sample) > 200 {
				sample = sample[:200]
			}
			log.Printf("status upload for endpoint %d (%s): %d bytes but 0 peers parsed — sample=%q", e.ID, e.Name, len(body), sample)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

type expectedPeer struct {
	Name       string `json:"name"`
	Owner      string `json:"owner"`
	PublicKey  string `json:"public_key"`
	AllowedIPs string `json:"allowed_ips"`
}

func (s *Server) handleExpectedPeers(w http.ResponseWriter, r *http.Request) {
	e, ok := s.authEndpoint(w, r)
	if !ok {
		return
	}
	machines, err := s.store.ActiveMachinesForEndpoint(e.ID)
	if err != nil {
		s.serverError(w, err)
		return
	}

	peers := make([]expectedPeer, 0, len(machines))
	for _, m := range machines {
		addr := m.Address
		if addr != "" && !strings.Contains(addr, "/") {
			addr += "/32"
		}
		peers = append(peers, expectedPeer{
			Name:       m.Name,
			Owner:      m.OwnerUID,
			PublicKey:  m.PublicKey,
			AllowedIPs: addr,
		})
	}

	switch r.URL.Query().Get("format") {
	case "wg":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		var b strings.Builder
		for _, p := range peers {
			fmt.Fprintf(&b, "[Peer]\n# %s (%s)\nPublicKey = %s\nAllowedIPs = %s\n\n",
				sanitizeComment(p.Name), sanitizeComment(p.Owner), p.PublicKey, p.AllowedIPs)
		}
		w.Write([]byte(b.String()))
		return
	case "tsv":
		// "<public-key>\t<allowed-ips>" per line — easy to consume from a shell
		// reconcile script (no jq needed).
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		var b strings.Builder
		for _, p := range peers {
			fmt.Fprintf(&b, "%s\t%s\n", p.PublicKey, p.AllowedIPs)
		}
		w.Write([]byte(b.String()))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Endpoint string         `json:"endpoint"`
		Peers    []expectedPeer `json:"peers"`
	}{e.Name, peers})
}

// handleEndpointConfigAPI returns the concentrator's own wg0.conf (interface +
// one peer per assigned machine), authenticated with the endpoint's upload
// token — the same credential used for status uploads and expected-peers. This
// lets a concentrator fetch its full config on first boot without a portal login.
func (s *Server) handleEndpointConfigAPI(w http.ResponseWriter, r *http.Request) {
	e, ok := s.authEndpoint(w, r)
	if !ok {
		return
	}
	machines, err := s.store.ActiveMachinesForEndpoint(e.ID)
	if err != nil {
		s.serverError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(wg.ConcentratorConfig(e, machines)))
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if after, found := strings.CutPrefix(h, "Bearer "); found {
		return strings.TrimSpace(after)
	}
	// Also accept a raw token in the header for convenience.
	return strings.TrimSpace(h)
}

// subtleEqual compares two secrets in constant time using the vetted primitive.
func subtleEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
