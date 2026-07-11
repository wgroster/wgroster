package web

import (
	"net/http"
	"time"

	"github.com/wgroster/wgroster/internal/store"
)

// Peer states shown on the status dashboard.
const (
	statePeerOnline  = "online"  // expected and handshaked recently
	statePeerOffline = "offline" // expected, reported, but stale/never
	statePeerMissing = "missing" // expected (active machine) but not reported
	statePeerExtra   = "extra"   // reported but not an expected machine
)

type peerStatus struct {
	Name           string
	Owner          string
	PublicKey      string
	Address        string // address assigned by the portal
	State          string
	RemoteEndpoint string // remote IP:port as seen by the hub
	HubAllowedIPs  string // allowed-ips as seen by the hub (server side)
	AddrMismatch   bool   // hub allowed-ips does not cover the assigned address
	LastHandshake  time.Time
	RX             int64
	TX             int64
	RxRate         int64 // bytes/s, from the last two reports
	TxRate         int64
}

type endpointStatus struct {
	E           *store.Endpoint
	LastReport  time.Time
	HasReport   bool
	ReportFresh bool
	Peers       []peerStatus
	Missing     int
	Extra       int
	OnlineN     int
	Series      []int64 // recent total throughput (bytes/s) for the sparkline
}

func (s *Server) buildStatus() ([]endpointStatus, error) {
	endpoints, err := s.store.ListEndpoints()
	if err != nil {
		return nil, err
	}

	out := make([]endpointStatus, 0, len(endpoints))
	for _, e := range endpoints {
		es := endpointStatus{E: e}

		last, ok, err := s.store.LastReport(e.ID)
		if err != nil {
			return nil, err
		}
		es.LastReport, es.HasReport = last, ok
		es.ReportFresh = ok && time.Since(last) < onlineThreshold

		expected, err := s.store.ActiveMachinesForEndpoint(e.ID)
		if err != nil {
			return nil, err
		}
		reported, err := s.store.PeersForEndpoint(e.ID)
		if err != nil {
			return nil, err
		}
		reportedByKey := make(map[string]store.StatusPeer, len(reported))
		for _, p := range reported {
			reportedByKey[p.PublicKey] = p
		}

		expectedKeys := make(map[string]bool, len(expected))
		for _, m := range expected {
			expectedKeys[m.PublicKey] = true
			ps := peerStatus{
				Name:      m.Name,
				Owner:     m.OwnerDisplay(),
				PublicKey: m.PublicKey,
				Address:   m.Address,
			}
			if p, ok := reportedByKey[m.PublicKey]; ok {
				ps.LastHandshake = p.LastHandshake
				ps.RX, ps.TX = p.RX, p.TX
				ps.RemoteEndpoint = p.RemoteEndpoint
				ps.HubAllowedIPs = p.AllowedIPs
				ps.AddrMismatch = m.Address != "" && p.AllowedIPs != "" && !allowedCovers(p.AllowedIPs, m.Address)
				if online(p.LastHandshake) {
					ps.State = statePeerOnline
					es.OnlineN++
				} else {
					ps.State = statePeerOffline
				}
			} else {
				ps.State = statePeerMissing
				es.Missing++
			}
			es.Peers = append(es.Peers, ps)
		}

		// Reported peers that are not expected (declared elsewhere or stale).
		for _, p := range reported {
			if expectedKeys[p.PublicKey] {
				continue
			}
			ps := peerStatus{
				PublicKey:      p.PublicKey,
				State:          statePeerExtra,
				RemoteEndpoint: p.RemoteEndpoint,
				HubAllowedIPs:  p.AllowedIPs,
				LastHandshake:  p.LastHandshake,
				RX:             p.RX,
				TX:             p.TX,
				Name:           "(unknown)",
			}
			if m, err := s.store.MachineByPublicKey(p.PublicKey); err == nil {
				ps.Name = m.Name
				ps.Owner = m.OwnerDisplay()
				ps.Address = m.Address
				ps.AddrMismatch = m.Address != "" && p.AllowedIPs != "" && !allowedCovers(p.AllowedIPs, m.Address)
			}
			es.Peers = append(es.Peers, ps)
			es.Extra++
		}

		// Per-peer throughput (rate) shown in the table; full curves live in the
		// peer drawer.
		if rates, err := s.store.EndpointThroughput(e.ID); err == nil {
			for i := range es.Peers {
				if r, ok := rates[es.Peers[i].PublicKey]; ok {
					es.Peers[i].RxRate, es.Peers[i].TxRate = r[0], r[1]
				}
			}
		}

		out = append(out, es)
	}
	return out, nil
}

// statusSummary wraps the per-endpoint statuses with network-wide totals.
type statusSummary struct {
	Endpoints  []endpointStatus
	EndpointN  int
	ReportingN int
	OnlineN    int
	MissingN   int
	ExtraN     int
}

func summarize(es []endpointStatus) statusSummary {
	sum := statusSummary{Endpoints: es, EndpointN: len(es)}
	for _, e := range es {
		if e.ReportFresh {
			sum.ReportingN++
		}
		sum.OnlineN += e.OnlineN
		sum.MissingN += e.Missing
		sum.ExtraN += e.Extra
	}
	return sum
}

func (s *Server) handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "admin_status", "Status", "status", nil)
}

func (s *Server) handleAdminStatusTable(w http.ResponseWriter, r *http.Request) {
	statuses, err := s.buildStatus()
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.renderPartial(w, "status_table", summarize(statuses))
}
