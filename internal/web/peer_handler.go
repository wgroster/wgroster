package web

import (
	"context"
	"net"
	"net/http"
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
	EndpointName   string
	PublicKey      string
	Name           string
	Owner          string
	Address        string
	State          string
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

	d := peerDetail{EndpointName: ep.Name, PublicKey: key, Name: "(unknown)", GeoEnabled: s.geo.Enabled()}

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

	// Machine identity (may be absent → unexpected peer).
	if m, err := s.store.MachineByPublicKey(key); err == nil {
		d.Name = m.Name
		d.Owner = m.OwnerDisplay()
		d.Address = m.Address
		if eps, err := s.store.EndpointsForMachine(m.ID); err == nil {
			for _, e := range eps {
				d.Endpoints = append(d.Endpoints, e.Name)
			}
		}
		if reported == nil {
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
		if d.Name == "(unknown)" {
			d.State = statePeerExtra
		} else if online(reported.LastHandshake) {
			d.State = statePeerOnline
		} else {
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

	// History → throughput sparklines + recent samples.
	if samples, err := s.store.PeerSeries(endpointID, key, 60); err == nil && len(samples) > 0 {
		d.FirstSeen, d.HasFirstSeen = samples[0].TS, true
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
