package wg

import (
	"strconv"
	"strings"
	"time"

	"github.com/wgroster/wgroster/internal/store"
)

// isKey reports whether s looks like a base64-encoded WireGuard key (44 chars
// ending with '='). Used to tell apart the "wg show <iface> dump" format (lines
// start with a key) from "wg show all dump" (lines start with an interface name).
func isKey(s string) bool {
	return len(s) == 44 && strings.HasSuffix(s, "=")
}

// ParseDump parses the output of either:
//
//	wg show <iface> dump
//	wg show all dump
//
// Fields are split on any run of whitespace, so the dump is parsed whether it
// arrives tab-separated (as wg emits it) or space-separated (e.g. after being
// reformatted in transit). No wg dump field contains whitespace, so this is
// unambiguous. It returns the peer entries (the interface "self" line is
// skipped); the EndpointID field is left at zero for the caller to fill in.
func ParseDump(raw string) []store.StatusPeer {
	var peers []store.StatusPeer

	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		// Normalise to "no interface prefix": drop the leading interface name
		// when present (all-dump format).
		var f []string
		if isKey(fields[0]) {
			f = fields
		} else {
			f = fields[1:]
		}

		// Self line: privkey, pubkey, listen-port, fwmark (4 fields). Peer line:
		// pubkey, psk, endpoint, allowed-ips, latest-handshake, rx, tx,
		// persistent-keepalive (8 fields).
		if len(f) < 8 {
			continue
		}

		var p store.StatusPeer
		p.PublicKey = f[0]
		if f[2] != "(none)" {
			p.RemoteEndpoint = f[2]
		}
		if f[3] != "(none)" {
			p.AllowedIPs = f[3]
		}
		if hs, err := strconv.ParseInt(f[4], 10, 64); err == nil && hs > 0 {
			p.LastHandshake = time.Unix(hs, 0)
		}
		p.RX, _ = strconv.ParseInt(f[5], 10, 64)
		p.TX, _ = strconv.ParseInt(f[6], 10, 64)

		peers = append(peers, p)
	}
	return peers
}
