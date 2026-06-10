// Command seed writes a realistic fake database for screenshots/demos.
//
//	go run ./tools/seed -db /tmp/fake.db
package main

import (
	"encoding/base64"
	"flag"
	"log"
	"time"

	"github.com/wgroster/wgroster/internal/store"
)

// k returns a deterministic valid-looking 44-char public key.
func k(b byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = b
	}
	return base64.StdEncoding.EncodeToString(raw)
}

type peerSample struct {
	key            byte
	remote         string
	allowed        string
	baseRX, baseTX int64
	rateRX, rateTX int64 // bytes added per 2-min step
	online         bool
}

// report builds a small time-series for an endpoint so throughput/sparklines
// render. The newest sample lands at now-lastOffset (>3min ⇒ stale endpoint).
func report(st *store.Store, epID int64, peers []peerSample, now time.Time, lastOffset time.Duration) {
	const steps = 8
	// Varying per-step weights → uneven throughput so the sparklines look alive.
	weights := []float64{0, 1.0, 1.9, 0.6, 2.3, 0.8, 1.6, 0.5}
	prefix := make([]float64, steps)
	acc := 0.0
	for i := 0; i < steps; i++ {
		acc += weights[i%len(weights)]
		prefix[i] = acc
	}
	for i := 0; i < steps; i++ {
		ts := now.Add(-lastOffset).Add(time.Duration(-(steps - 1 - i)) * 2 * time.Minute)
		var sp []store.StatusPeer
		for _, p := range peers {
			hs := now.Add(-25 * time.Minute) // offline default
			if p.online {
				hs = ts
			}
			sp = append(sp, store.StatusPeer{
				PublicKey:      k(p.key),
				RemoteEndpoint: p.remote,
				AllowedIPs:     p.allowed,
				RX:             p.baseRX + int64(float64(p.rateRX)*prefix[i]),
				TX:             p.baseTX + int64(float64(p.rateTX)*prefix[(i+3)%steps]),
				LastHandshake:  hs,
			})
		}
		if err := st.ReplaceStatus(epID, sp, ts); err != nil {
			log.Fatalf("report: %v", err)
		}
	}
}

func main() {
	dbPath := flag.String("db", "fake.db", "path to the SQLite file to (re)create")
	flag.Parse()

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	defer st.Close()
	now := time.Now()

	paris := &store.Endpoint{Name: "paris", PublicKey: k(200), HostPort: "vpn-par.example.com:51820", AllowedIPs: "10.0.0.0/8", DNS: "10.0.0.1", PersistentKeepalive: 25, TunnelIP: "10.0.0.1", UploadToken: "tok-paris"}
	fra := &store.Endpoint{Name: "frankfurt", PublicKey: k(201), HostPort: "vpn-fra.example.com:51820", AllowedIPs: "10.0.0.0/8", DNS: "10.0.0.1", PersistentKeepalive: 25, UploadToken: "tok-fra"}
	ams := &store.Endpoint{Name: "amsterdam", PublicKey: k(202), HostPort: "vpn-ams.example.com:51820", AllowedIPs: "100.64.0.0/10", PersistentKeepalive: 25, UploadToken: "tok-ams"}
	nyc := &store.Endpoint{Name: "newyork", PublicKey: k(203), HostPort: "vpn-nyc.example.com:51820", AllowedIPs: "10.0.0.0/8", PersistentKeepalive: 25, UploadToken: "tok-nyc"}
	for _, e := range []*store.Endpoint{paris, fra, ams, nyc} {
		if err := st.CreateEndpoint(e); err != nil {
			log.Fatalf("endpoint %s: %v", e.Name, err)
		}
	}

	type machine struct {
		uid, cn, name string
		key           byte
		addr          string
		ep            *store.Endpoint
		active        bool
	}
	for _, m := range []machine{
		{"admin", "Admin", "admin-laptop", 7, "10.0.0.2", paris, true},
		{"admin", "Admin", "old-phone", 8, "", paris, false}, // pending (own dashboard)
		{"alice", "Alice Martin", "macbook", 1, "10.0.0.5", paris, true},
		{"alice", "Alice Martin", "iphone", 2, "10.0.0.6", paris, true},
		{"bob", "Bob Durand", "thinkpad", 3, "10.0.0.10", fra, true},
		{"bob", "Bob Durand", "home-desktop", 4, "", fra, false}, // pending
		{"carol", "Carole Petit", "macbook-pro", 5, "100.64.0.20", ams, true},
		{"dave", "David Roy", "backup-server", 6, "100.64.0.30", ams, true}, // missing on hub
	} {
		mm := &store.Machine{OwnerUID: m.uid, OwnerName: m.cn, Name: m.name, PublicKey: k(m.key)}
		if err := st.CreateMachine(mm); err != nil {
			log.Fatalf("machine %s: %v", m.name, err)
		}
		if m.active {
			if err := st.ApproveMachine(mm.ID, m.addr, []int64{m.ep.ID}, "admin"); err != nil {
				log.Fatalf("approve %s: %v", m.name, err)
			}
		}
	}

	// paris: two online peers; iphone has an AllowedIPs mismatch (10.9.9.9 ≠ .6).
	report(st, paris.ID, []peerSample{
		{key: 7, remote: "203.0.113.30:51820", allowed: "10.0.0.2/32", baseRX: 9_000_000, baseTX: 21_000_000, rateRX: 2_100_000, rateTX: 1_300_000, online: true},
		{key: 1, remote: "203.0.113.10:57571", allowed: "10.0.0.5/32", baseRX: 2_000_000, baseTX: 8_000_000, rateRX: 1_500_000, rateTX: 900_000, online: true},
		{key: 2, remote: "203.0.113.20:51820", allowed: "10.9.9.9/32", baseRX: 400_000, baseTX: 1_200_000, rateRX: 300_000, rateTX: 250_000, online: true},
	}, now, 0)

	// frankfurt: one offline peer (reporting endpoint, peer last seen 25m ago).
	report(st, fra.ID, []peerSample{
		{key: 3, remote: "", allowed: "10.0.0.10/32", baseRX: 50_000_000, baseTX: 12_000_000, online: false},
	}, now, 0)

	// amsterdam: carol online with rich traffic, plus an unexpected peer; dave is
	// linked but never reported → missing on hub.
	report(st, ams.ID, []peerSample{
		{key: 5, remote: "198.51.100.40:16359", allowed: "100.64.0.20/32", baseRX: 120_000_000, baseTX: 30_000_000, rateRX: 6_000_000, rateTX: 2_200_000, online: true},
		{key: 250, remote: "198.51.100.99:1234", allowed: "100.64.0.99/32", baseRX: 5_000_000, baseTX: 800_000, rateRX: 400_000, rateTX: 120_000, online: true},
	}, now, 0)

	// nyc: no report at all → "no data".

	for _, a := range []struct{ actor, action, target string }{
		{"admin", "endpoint.create", "paris"},
		{"admin", "endpoint.create", "frankfurt"},
		{"admin", "machine.create", "alice/macbook"},
		{"alice", "machine.enroll", "alice/iphone"},
		{"admin", "machine.update", "carol/macbook-pro"},
		{"admin", "endpoint.token_regen", "amsterdam"},
	} {
		if err := st.AddAudit(a.actor, a.action, a.target); err != nil {
			log.Fatalf("audit: %v", err)
		}
	}

	log.Printf("seeded %s", *dbPath)
}
