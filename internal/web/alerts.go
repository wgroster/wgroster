package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// alertPayload is POSTed to the configured webhook on a state transition.
type alertPayload struct {
	Endpoint string `json:"endpoint"`
	Type     string `json:"type"`   // stale | missing | unlinked | unexpected | mismatch
	Status   string `json:"status"` // firing | resolved
	Detail   string `json:"detail"`
	Time     string `json:"time"`
}

// RunAlerts periodically evaluates endpoint health and POSTs the webhook on
// transitions. It returns immediately if no webhook is configured. Cancel ctx
// to stop. Tracking-only: it never contacts the concentrators.
func (s *Server) RunAlerts(ctx context.Context) {
	if s.cfg.AlertWebhookURL == "" {
		return
	}
	firing := map[alertKey]string{} // alert -> detail while it is firing
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		s.evalAlerts(ctx, firing)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// alertKey identifies one alert: a condition type on a given endpoint.
type alertKey struct {
	endpoint string
	typ      string // stale | missing | unlinked | unexpected | mismatch
}

func (s *Server) evalAlerts(ctx context.Context, firing map[alertKey]string) {
	statuses, err := s.status()
	if err != nil {
		log.Printf("alerts: %v", err)
		return
	}

	current := map[alertKey]string{}
	add := func(name, typ, detail string) { current[alertKey{name, typ}] = detail }
	for _, es := range statuses {
		if es.HasReport && !es.ReportFresh {
			add(es.E.Name, "stale", fmt.Sprintf("no report for %s", ago(es.LastReport)))
		}
		if es.Missing > 0 {
			add(es.E.Name, "missing", fmt.Sprintf("%d peer(s) missing on hub", es.Missing))
		}
		if es.Unlinked > 0 {
			add(es.E.Name, "unlinked", fmt.Sprintf("%d peer(s) known to the portal but not active here", es.Unlinked))
		}
		if es.Extra > 0 {
			add(es.E.Name, "unexpected", fmt.Sprintf("%d peer(s) with an unknown public key", es.Extra))
		}
		n := 0
		for _, p := range es.Peers {
			if p.AddrMismatch {
				n++
			}
		}
		if n > 0 {
			add(es.E.Name, "mismatch", fmt.Sprintf("%d peer(s) with AllowedIPs mismatch", n))
		}
	}

	// Newly firing.
	for key, detail := range current {
		if _, was := firing[key]; !was {
			s.postAlert(ctx, key, "firing", detail)
		}
		firing[key] = detail
	}
	// Resolved.
	for key := range firing {
		if _, still := current[key]; !still {
			s.postAlert(ctx, key, "resolved", "")
			delete(firing, key)
		}
	}
}

func (s *Server) postAlert(ctx context.Context, key alertKey, status, detail string) {
	body, _ := json.Marshal(alertPayload{
		Endpoint: key.endpoint, Type: key.typ, Status: status, Detail: detail,
		Time: time.Now().Format(time.RFC3339),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.AlertWebhookURL, bytes.NewReader(body))
	if err != nil {
		log.Printf("alert webhook: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("alert webhook: %v", err)
		return
	}
	resp.Body.Close()
}
