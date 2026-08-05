package web

import (
	"io"
	"testing"
	"time"

	"github.com/wgroster/wgroster/internal/auth"
	"github.com/wgroster/wgroster/internal/geoip"
	"github.com/wgroster/wgroster/internal/store"
)

// TestTemplatesExecute parses every template and executes it with representative
// data, catching both syntax errors and bad field paths.
func TestTemplatesExecute(t *testing.T) {
	if err := loadTemplates(); err != nil {
		t.Fatalf("loadTemplates: %v", err)
	}

	sess := &auth.Session{UID: "alice", Name: "Alice Example", Admin: true, Local: true, CSRF: "tok"}
	m := &store.Machine{ID: 1, OwnerUID: "alice", Name: "laptop", PublicKey: "k", Address: "10.0.0.5", Status: store.StatusActive}
	ep := &store.Endpoint{ID: 1, Name: "paris", HostPort: "vpn:51820", PublicKey: "k", UploadToken: "t"}

	data := map[string]any{
		"login":     nil,
		"dashboard": []machineView{{M: m, Endpoints: []*store.Endpoint{ep}, Online: true, LastHandshake: time.Now()}},
		"machine_config": struct {
			Machine *store.Machine
			Config  string
		}{m, "config text"},
		"admin_machines": struct {
			Groups       []*userGroup
			AllEndpoints []*store.Endpoint
			SuggestedIP  string
			TotalPending int
		}{
			[]*userGroup{{
				UID:      "alice",
				Name:     "Alice Example",
				Total:    1,
				OnlineN:  1,
				Machines: []adminMachineView{{M: m, EndpointNames: []string{"paris"}, SelectedIDs: map[int64]bool{1: true}, Online: true}},
			}},
			[]*store.Endpoint{ep},
			"10.0.0.6",
			1,
		},
		"admin_endpoints": struct {
			Endpoints []endpointAdminView
			BaseURL   string
		}{
			[]endpointAdminView{{E: ep, ExpectedN: 2, HasReport: true, ReportFresh: true, LastReport: time.Now()}},
			"https://wg.example.com",
		},
		"admin_audit": []store.AuditEntry{
			{TS: time.Now(), Actor: "admin", Action: "machine.create", Target: "alice/laptop"},
		},
		"admin_status": []endpointStatus{},
	}

	for _, page := range fullPages {
		t.Run(page, func(t *testing.T) {
			pd := pageData{Title: "t", Session: sess, SelfEnroll: true, Data: data[page]}
			if err := pageTmpls[page].ExecuteTemplate(io.Discard, "layout", pd); err != nil {
				t.Errorf("execute %s: %v", page, err)
			}
		})
	}

	// Partial with one fully populated endpoint status, wrapped in a summary.
	statuses := []endpointStatus{{
		E:           ep,
		LastReport:  time.Now(),
		HasReport:   true,
		ReportFresh: true,
		OnlineN:     1,
		Missing:     1,
		Unlinked:    2,
		Extra:       1,
		Series:      []int64{10, 50, 30, 80, 20, 60},
		Peers: []peerStatus{
			{Name: "laptop", Owner: "alice", Address: "10.0.0.5", State: statePeerOnline, RemoteEndpoint: "203.0.113.5:1234", HubAllowedIPs: "10.0.0.5/32", LastHandshake: time.Now(), RX: 1024, TX: 2048, RxRate: 1500, TxRate: 800},
			{Name: "desktop", Owner: "alice", Address: "10.0.0.6", State: statePeerOffline, HubAllowedIPs: "10.0.0.99/32", AddrMismatch: true},
			{Name: "tablet", Owner: "bob", Address: "10.0.0.7", State: statePeerUnlinked, HubAllowedIPs: "10.0.0.7/32"},
			{Name: "phone", Owner: "bob", State: statePeerUnlinked, Pending: true, HubAllowedIPs: "10.0.0.8/32"},
			{Name: "(unknown)", State: statePeerExtra, RemoteEndpoint: "198.51.100.7:51820", HubAllowedIPs: "10.0.0.200/32"},
		},
	}}
	if err := partialTmpls["status_table"].ExecuteTemplate(io.Discard, "status_table", summarize(statuses)); err != nil {
		t.Errorf("execute status_table: %v", err)
	}

	drawer := peerDetail{
		EndpointName: "amsterdam", PublicKey: "k", Name: "laptop", Owner: "alice", Address: "10.0.0.5",
		State: statePeerOnline, Endpoints: []string{"amsterdam"}, RemoteEndpoint: "203.0.113.4:51820",
		PTR: "host.example.net", GeoEnabled: true,
		Geo:           geoip.Result{Country: "FR", City: "Paris", ASN: "AS3215", Org: "Orange"},
		LastHandshake: time.Now(), FirstSeen: time.Now(), HasFirstSeen: true,
		RX: 1000, TX: 2000, RxRate: 500, TxRate: 100, HubAllowedIPs: "10.0.0.5/32",
		RxSpark: []int64{1, 2, 3}, TxSpark: []int64{1, 1, 2},
		Recent: []recentSample{{TS: time.Now(), RxRate: 500, TxRate: 100}},
	}
	if err := partialTmpls["peer_drawer"].ExecuteTemplate(io.Discard, "peer_drawer", drawer); err != nil {
		t.Errorf("execute peer_drawer: %v", err)
	}

	// Drift variants: each renders its own action form, so exercise them all.
	drifts := map[string]peerDetail{
		"extra": {
			EndpointID: 1, EndpointName: "amsterdam", CSRF: "tok", PublicKey: "k", Name: "(unknown)",
			State: statePeerExtra, HubAllowedIPs: "10.0.0.200/32", Suggested: "10.0.0.200", SuggestedIsHub: true,
		},
		"extra address outside pool": {
			EndpointID: 1, EndpointName: "amsterdam", CSRF: "tok", PublicKey: "k", Name: "(unknown)",
			State: statePeerExtra, HubAllowedIPs: "192.0.2.9/32", Suggested: "10.0.0.9",
		},
		"unlinked": {
			EndpointID: 1, EndpointName: "amsterdam", CSRF: "tok", PublicKey: "k", Name: "laptop", Owner: "alice",
			MachineID: 1, Address: "10.0.0.5", Endpoints: []string{"paris"}, State: statePeerUnlinked,
			HubAllowedIPs: "10.0.0.99/32", AddrMismatch: true, Suggested: "10.0.0.5",
		},
		"pending": {
			EndpointID: 1, EndpointName: "amsterdam", CSRF: "tok", PublicKey: "k", Name: "phone", Owner: "bob",
			MachineID: 2, Pending: true, LinkedHere: true, State: statePeerUnlinked,
			HubAllowedIPs: "10.0.0.8/32", Suggested: "10.0.0.8", SuggestedIsHub: true,
		},
	}
	for name, d := range drifts {
		if err := partialTmpls["peer_drawer"].ExecuteTemplate(io.Discard, "peer_drawer", d); err != nil {
			t.Errorf("execute peer_drawer (%s): %v", name, err)
		}
	}
}
