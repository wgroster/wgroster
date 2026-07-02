package wg

import (
	"strings"
	"testing"

	"github.com/wgroster/wgroster/internal/store"
)

func TestParseDumpSingleInterface(t *testing.T) {
	// "wg show wg0 dump": first line is the interface self line, then peers.
	raw := strings.Join([]string{
		"aPrivKeyaPrivKeyaPrivKeyaPrivKeyaPrivKeyaaa=\tsSelfPubKeysSelfPubKeysSelfPubKeysSelfPubK=\t51820\toff",
		"cClientPubKeycClientPubKeycClientPubKeycCli=\t(none)\t203.0.113.5:1234\t10.0.0.5/32\t1700000000\t1024\t2048\t25",
		"dOfflinePubKeydOfflinePubKeydOfflinePubKeyd=\t(none)\t(none)\t10.0.0.6/32\t0\t0\t0\t0",
	}, "\n")

	peers := ParseDump(raw)
	if len(peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(peers))
	}
	if peers[0].PublicKey != "cClientPubKeycClientPubKeycClientPubKeycCli=" {
		t.Errorf("unexpected public key %q", peers[0].PublicKey)
	}
	if peers[0].RemoteEndpoint != "203.0.113.5:1234" {
		t.Errorf("unexpected endpoint %q", peers[0].RemoteEndpoint)
	}
	if peers[0].AllowedIPs != "10.0.0.5/32" {
		t.Errorf("unexpected allowed-ips %q", peers[0].AllowedIPs)
	}
	if peers[0].RX != 1024 || peers[0].TX != 2048 {
		t.Errorf("unexpected transfer %d/%d", peers[0].RX, peers[0].TX)
	}
	if peers[0].LastHandshake.IsZero() {
		t.Error("expected a handshake time")
	}
	if !peers[1].LastHandshake.IsZero() {
		t.Error("expected zero handshake for never-connected peer")
	}
}

func TestParseDumpAllInterfaces(t *testing.T) {
	// "wg show all dump": every line is prefixed with the interface name.
	raw := strings.Join([]string{
		"wg0\taPrivKeyaPrivKeyaPrivKeyaPrivKeyaPrivKeyaaa=\tsSelfPubKeysSelfPubKeysSelfPubKeysSelfPubK=\t51820\toff",
		"wg0\tcClientPubKeycClientPubKeycClientPubKeycCli=\tpPSKpPSKpPSKpPSKpPSKpPSKpPSKpPSKpPSKpPSKpP=\t203.0.113.5:1234\t10.0.0.5/32\t1700000000\t1024\t2048\t25",
	}, "\n")

	peers := ParseDump(raw)
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if peers[0].PublicKey != "cClientPubKeycClientPubKeycClientPubKeycCli=" {
		t.Errorf("unexpected public key %q", peers[0].PublicKey)
	}
}

// realRows is a real "wg show all dump" (1 interface line + 8 peers).
var realRows = [][]string{
	{"wg0", "gK5DNXyd5uoEyTNBp6tnHlDUoUmvZoi8kUzMuB81z2s=", "P26TkeJ3OPgiBXZUXO8tZZ8frHYc4Pb7ygKx5eoMuDo=", "51820", "off"},
	{"wg0", "vxJcAB+sHUkKndxbPGsSNwEU09yFyiUXbmr05CUOYBc=", "(none)", "176.143.251.237:57571", "100.64.31.5/32", "1780426782", "278557656", "600163524", "off"},
	{"wg0", "i9FcMqYtZB60GTEru/FTAMlH4xirSgV1dl1pBXigeyE=", "(none)", "89.85.242.203:5543", "100.64.31.7/32", "1780426677", "34645388", "260704156", "off"},
	{"wg0", "OfIhiqhj5i0E8j8/ArkBmWFcJuL0U9ZXcc4QKOKBmy4=", "(none)", "176.142.195.27:54324", "100.64.31.9/32", "1780034481", "1391200", "1944020", "off"},
	{"wg0", "DC6+IdkNK6yyYiMgOfYs9cLzal2NSjkB6xJIKfC/nzE=", "(none)", "176.190.208.188:16359", "100.64.31.11/32", "1780426693", "8543268", "13746996", "off"},
	{"wg0", "HXRcB4C63bQpGSUOVPWnKAyMVkZfqM1yW5oFQQYcjkY=", "(none)", "(none)", "100.64.31.15/32", "0", "0", "0", "off"},
	{"wg0", "YKOMtBw1QOoA1X/so7LjQA+P5ymli8g9N9jnh46iyUM=", "(none)", "(none)", "100.64.31.21/32", "0", "0", "0", "off"},
	{"wg0", "tx9euJaA7jrSrTP8SLSyVngzr/76UONEQdFq5Cd1rBQ=", "(none)", "(none)", "100.64.31.205/32", "0", "0", "0", "off"},
	{"wg0", "9XIYk+Y7QFEA9IKkD19vnooL5Qaexi6emdHhLRkn6DI=", "(none)", "(none)", "100.64.31.206/32", "0", "0", "0", "off"},
}

func TestParseDumpRealWorld(t *testing.T) {
	// The same dump must parse whether fields are separated by tabs (as wg
	// emits) or by spaces (if reformatted in transit).
	for _, sep := range []string{"\t", "    "} {
		lines := make([]string, len(realRows))
		for i, row := range realRows {
			lines[i] = strings.Join(row, sep)
		}
		peers := ParseDump(strings.Join(lines, "\n"))
		if len(peers) != 8 {
			t.Fatalf("sep=%q: expected 8 peers, got %d", sep, len(peers))
		}
		p := peers[0]
		if p.PublicKey != "vxJcAB+sHUkKndxbPGsSNwEU09yFyiUXbmr05CUOYBc=" {
			t.Errorf("sep=%q: pubkey %q", sep, p.PublicKey)
		}
		if p.RemoteEndpoint != "176.143.251.237:57571" {
			t.Errorf("sep=%q: endpoint %q", sep, p.RemoteEndpoint)
		}
		if p.AllowedIPs != "100.64.31.5/32" {
			t.Errorf("sep=%q: allowed-ips %q", sep, p.AllowedIPs)
		}
		if p.LastHandshake.Unix() != 1780426782 {
			t.Errorf("sep=%q: handshake %d", sep, p.LastHandshake.Unix())
		}
		if p.RX != 278557656 || p.TX != 600163524 {
			t.Errorf("sep=%q: rx/tx %d/%d", sep, p.RX, p.TX)
		}
		// Never-connected peer keeps a zero handshake.
		if !peers[4].LastHandshake.IsZero() {
			t.Errorf("sep=%q: expected zero handshake for peer 5", sep)
		}
	}
}

func TestClientConfig(t *testing.T) {
	m := &store.Machine{Name: "laptop", Address: "10.0.0.5", PublicKey: "x"}
	eps := []*store.Endpoint{
		{Name: "paris", PublicKey: "PARpubkey", HostPort: "vpn-par:51820", AllowedIPs: "192.168.1.0/24", DNS: "10.0.0.1", PersistentKeepalive: 25},
		{Name: "nyc", PublicKey: "NYCpubkey", HostPort: "vpn-nyc:51820", AllowedIPs: "192.168.2.0/24"},
	}
	conf := ClientConfig(m, eps)

	for _, want := range []string{
		"Address = 10.0.0.5/32",
		"DNS = 10.0.0.1",
		"Endpoint = vpn-par:51820",
		"AllowedIPs = 192.168.1.0/24",
		"PersistentKeepalive = 25",
		"Endpoint = vpn-nyc:51820",
		"<YOUR_PRIVATE_KEY>",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("config missing %q\n---\n%s", want, conf)
		}
	}
	if strings.Count(conf, "[Peer]") != 2 {
		t.Errorf("expected 2 peers, config:\n%s", conf)
	}
}

func TestConcentratorConfig(t *testing.T) {
	e := &store.Endpoint{Name: "par02", PublicKey: "HUBpubkey", HostPort: "vpn-par02.example.com:51820", TunnelIP: "10.76.0.1", MTU: 1420}
	machines := []*store.Machine{
		{Name: "laptop", OwnerUID: "alice", PublicKey: "LAPpubkey", Address: "10.76.1.5"},
		{Name: "phone", OwnerUID: "bob", PublicKey: "PHOpubkey", Address: "10.76.1.6/32"},
	}
	conf := ConcentratorConfig(e, machines)

	for _, want := range []string{
		"[Interface]",
		"# par02 concentrator",
		"<CONCENTRATOR_PRIVATE_KEY>",
		"Address = 10.76.0.1/32",
		"ListenPort = 51820",
		"MTU = 1420",
		"# laptop (alice)",
		"PublicKey = LAPpubkey",
		"AllowedIPs = 10.76.1.5/32",
		"# phone (bob)",
		"AllowedIPs = 10.76.1.6/32",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("config missing %q\n---\n%s", want, conf)
		}
	}
	if strings.Count(conf, "[Peer]") != 2 {
		t.Errorf("expected 2 peers, config:\n%s", conf)
	}
}
