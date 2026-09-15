package web

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
)

func parseInt64(s string) (int64, error) { return strconv.ParseInt(s, 10, 64) }

// allowedCovers reports whether the hub's allowed-ips list (comma-separated)
// covers the assigned address. Returns true when it cannot be judged, so an
// unparseable value never raises a false mismatch alert.
func allowedCovers(list, addr string) bool {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return true
	}
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		switch {
		case part == "":
			continue
		case strings.Contains(part, "/"):
			if pfx, err := netip.ParsePrefix(part); err == nil && pfx.Contains(a) {
				return true
			}
		default:
			if p, err := netip.ParseAddr(part); err == nil && p == a {
				return true
			}
		}
	}
	return false
}

// onlineThreshold is how recent a handshake must be for a peer to count as up.
const onlineThreshold = 3 * time.Minute

// validPublicKey performs a light sanity check on a WireGuard public key: 44
// base64 characters ending with '='.
func validPublicKey(k string) bool {
	k = strings.TrimSpace(k)
	if len(k) != 44 || !strings.HasSuffix(k, "=") {
		return false
	}
	for _, c := range k[:43] {
		isBase64 := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/'
		if !isBase64 {
			return false
		}
	}
	return true
}

// sanitizeComment makes a user-supplied label safe to emit on a single comment
// line of a generated WireGuard config. Input is validated by validName at every
// write path, but this is defense in depth at the rendering sink: any control
// character (notably newlines) is replaced with a space so a stored value can
// never break out of the "# name (owner)" line into an injected directive.
func sanitizeComment(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}

// hasControlChar reports whether s contains any control character (notably a
// newline). Endpoint fields are written line-by-line into generated WireGuard
// configs, so a newline would let extra directives be injected.
func hasControlChar(s string) bool {
	for _, r := range s {
		if r == '\n' || r == '\r' || unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func online(handshake time.Time) bool {
	return !handshake.IsZero() && time.Since(handshake) < onlineThreshold
}

// validName reports whether a user-supplied label (machine name, owner) is safe
// to store and later render. It must be non-empty after trimming and must not
// contain control characters. Rejecting newlines in particular prevents
// WireGuard config injection: names are emitted into the "# name" comment of a
// [Peer] block by handleExpectedPeers (format=wg), so an embedded newline could
// inject an attacker-controlled PublicKey/AllowedIPs line.
func validName(s string) bool {
	if strings.TrimSpace(s) == "" {
		return false
	}
	for _, r := range s {
		if r == '\n' || r == '\r' || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// validHostPort checks the "host:port" an endpoint is reached at. The host may
// be a name or a literal IP; the port must be a real port number.
func validHostPort(hp string) error {
	host, port, err := net.SplitHostPort(hp)
	if err != nil {
		return fmt.Errorf("%q must be host:port (e.g. vpn.example.com:51820)", hp)
	}
	if host == "" {
		return fmt.Errorf("%q has no host part", hp)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%q is not a valid port", port)
	}
	return nil
}

// validDNSList checks a WireGuard DNS list. Entries are resolver addresses, but
// wg-quick also accepts a hostname there as a search domain, so both are allowed
// — the point is to catch a typo, not to narrow what WireGuard supports.
func validDNSList(list string) error {
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, err := netip.ParseAddr(part); err == nil {
			continue
		}
		// Digits and dots only: that was meant to be an address, not a domain —
		// "300.1.1.1" is a legal hostname but never what anyone typed on purpose.
		if strings.IndexFunc(part, func(r rune) bool { return r != '.' && (r < '0' || r > '9') }) < 0 {
			return fmt.Errorf("%q is not a valid DNS server address", part)
		}
		if !isHostname(part) {
			return fmt.Errorf("%q is not a valid DNS server address or search domain", part)
		}
	}
	return nil
}

func isHostname(s string) bool {
	if len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(s, "."), ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i, r := range label {
			alnum := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
			if !alnum && !(r == '-' && i > 0 && i < len(label)-1) {
				return false
			}
		}
	}
	return true
}

// parseEndpointIDs reads repeated "endpoint_ids" form values into int64s.
func parseEndpointIDs(values []string) []int64 {
	var out []int64
	for _, v := range values {
		if id, err := parseInt64(v); err == nil {
			out = append(out, id)
		}
	}
	return out
}
