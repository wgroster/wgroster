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
	// statePeerUnlinked: reported by the hub and the key is known to the portal,
	// but the machine is not active on this endpoint (pending approval, or linked
	// to other endpoints only). One click away from being correct.
	statePeerUnlinked = "unlinked"
	// statePeerExtra: reported by the hub with a public key the portal has never
	// seen. Either a config predating the portal (adopt it) or a peer that should
	// be removed from the concentrator.
	statePeerExtra = "extra"
)

type peerStatus struct {
	Name           string
	Owner          string
	PublicKey      string
	Address        string // address assigned by the portal
	State          string
	Pending        bool   // known machine still awaiting approval (unlinked only)
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
	Unlinked    int
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

		// Reported peers the portal does not expect here. Two very different
		// cases, kept apart because they call for different fixes: a key the
		// portal knows (unlinked → link/approve the machine) versus a key it has
		// never seen (extra → adopt it or clean up the hub).
		for _, p := range reported {
			if expectedKeys[p.PublicKey] {
				continue
			}
			ps := peerStatus{
				PublicKey:      p.PublicKey,
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
				ps.Pending = m.Status == store.StatusPending
				ps.State = statePeerUnlinked
				es.Unlinked++
			} else {
				ps.State = statePeerExtra
				es.Extra++
			}
			es.Peers = append(es.Peers, ps)
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
	UnlinkedN  int
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
		sum.UnlinkedN += e.Unlinked
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
