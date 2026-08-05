package web

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/wgroster/wgroster/internal/store"
)

// handleMetrics exposes a Prometheus text exposition of the fleet status. When
// a metrics_token is configured it must be supplied as a bearer token.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.metricsAllowed(r) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	statuses, err := s.buildStatus()
	if err != nil {
		s.serverError(w, err)
		return
	}
	machines, err := s.store.ListMachines()
	if err != nil {
		s.serverError(w, err)
		return
	}

	var b strings.Builder
	gauge := func(name, help string) { fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name) }

	reporting := 0
	var pending int
	for _, m := range machines {
		if m.Status == store.StatusPending {
			pending++
		}
	}
	for _, es := range statuses {
		if es.ReportFresh {
			reporting++
		}
	}

	gauge("wg_endpoints_total", "Number of declared endpoints.")
	fmt.Fprintf(&b, "wg_endpoints_total %d\n", len(statuses))
	gauge("wg_endpoints_reporting", "Endpoints with a fresh status report.")
	fmt.Fprintf(&b, "wg_endpoints_reporting %d\n", reporting)
	gauge("wg_machines_total", "Total registered machines.")
	fmt.Fprintf(&b, "wg_machines_total %d\n", len(machines))
	gauge("wg_machines_pending", "Machines awaiting approval.")
	fmt.Fprintf(&b, "wg_machines_pending %d\n", pending)

	gauge("wg_peers_online", "Expected peers seen online, per endpoint.")
	for _, es := range statuses {
		fmt.Fprintf(&b, "wg_peers_online{endpoint=%q} %d\n", escapeLabel(es.E.Name), es.OnlineN)
	}
	gauge("wg_peers_offline", "Expected peers reported but stale, per endpoint.")
	for _, es := range statuses {
		fmt.Fprintf(&b, "wg_peers_offline{endpoint=%q} %d\n", escapeLabel(es.E.Name), countState(es, statePeerOffline))
	}
	gauge("wg_peers_missing", "Expected peers absent from the hub report, per endpoint.")
	for _, es := range statuses {
		fmt.Fprintf(&b, "wg_peers_missing{endpoint=%q} %d\n", escapeLabel(es.E.Name), es.Missing)
	}
	gauge("wg_peers_unlinked", "Reported peers whose key is known to the portal but not active on this endpoint.")
	for _, es := range statuses {
		fmt.Fprintf(&b, "wg_peers_unlinked{endpoint=%q} %d\n", escapeLabel(es.E.Name), es.Unlinked)
	}
	gauge("wg_peers_unexpected", "Reported peers whose public key is unknown to the portal, per endpoint.")
	for _, es := range statuses {
		fmt.Fprintf(&b, "wg_peers_unexpected{endpoint=%q} %d\n", escapeLabel(es.E.Name), es.Extra)
	}

	gauge("wg_last_report_age_seconds", "Seconds since the last status report, per endpoint.")
	for _, es := range statuses {
		if es.HasReport {
			fmt.Fprintf(&b, "wg_last_report_age_seconds{endpoint=%q} %d\n",
				escapeLabel(es.E.Name), int64(time.Since(es.LastReport).Seconds()))
		}
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Write([]byte(b.String()))
}

// metricsAllowed permits scraping with the configured metrics token, or by an
// authenticated administrator session. /metrics is never anonymous.
func (s *Server) metricsAllowed(r *http.Request) bool {
	if s.cfg.MetricsToken != "" && subtleEqual(bearerToken(r), s.cfg.MetricsToken) {
		return true
	}
	if sess, err := s.sess.Read(r); err == nil && sess.Admin {
		return true
	}
	return false
}

func countState(es endpointStatus, state string) int {
	n := 0
	for _, p := range es.Peers {
		if p.State == state {
			n++
		}
	}
	return n
}

func escapeLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return v
}
