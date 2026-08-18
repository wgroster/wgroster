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
	Name            string
	Owner           string
	OwnerUID        string // owner's uid, for the avatar URL; empty for an unknown key
	HasPhoto        bool   // a directory photo is cached (served at /avatar/{uid})
	SameOwnerAsPrev bool   // previous row has the same owner: name and avatar are printed once per run
	PublicKey       string
	Address         string // address assigned by the portal
	State           string
	Pending         bool   // known machine still awaiting approval (unlinked only)
	RemoteEndpoint  string // remote IP:port as seen by the hub
	HubAllowedIPs   string // allowed-ips as seen by the hub (server side)
	AddrMismatch    bool   // hub allowed-ips does not cover the assigned address
	LastHandshake   time.Time
	RX              int64
	TX              int64
	RxRate          int64 // bytes/s, from the last two reports
	TxRate          int64
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

	// Owner identity comes from a single profiles query for the whole build: this
	// runs on every status poll (and every /metrics scrape), and each query goes
	// through the single serialized SQLite connection.
	profiles, err := s.store.AllUserProfileMetas()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var ownerUIDs []string
	setOwner := func(ps *peerStatus, m *store.Machine) {
		ps.OwnerUID = m.OwnerUID
		ps.Owner = m.OwnerDisplay()
		if !seen[m.OwnerUID] {
			seen[m.OwnerUID] = true
			ownerUIDs = append(ownerUIDs, m.OwnerUID)
		}
		p := profiles[m.OwnerUID]
		// The directory name wins over the copy cached on the machine row.
		if p.DisplayName != "" {
			ps.Owner = p.DisplayName
		}
		ps.HasPhoto = p.HasPhoto
	}

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
				PublicKey: m.PublicKey,
				Address:   m.Address,
			}
			setOwner(&ps, m)
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
				ps.Address = m.Address
				setOwner(&ps, m)
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

		// Consecutive rows of the same owner are visually grouped by the template,
		// so the avatar and name are printed once per run instead of on every
		// line. Expected peers already arrive ordered by owner; the reported-but-
		// unexpected ones appended above are not, and simply do not group.
		for i := 1; i < len(es.Peers); i++ {
			if uid := es.Peers[i].OwnerUID; uid != "" && uid == es.Peers[i-1].OwnerUID {
				es.Peers[i].SameOwnerAsPrev = true
			}
		}

		out = append(out, es)
	}

	// Lazily refresh missing or stale directory profiles in the background, so
	// names and avatars appear on a subsequent poll (no-op without LDAP).
	s.refreshProfilesAsync(ownerUIDs, profiles)

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
