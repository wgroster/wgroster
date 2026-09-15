package wg

import (
	"fmt"
	"net/netip"
	"strings"
)

// DefaultAllowedIPs is what a client [Peer] gets when an endpoint declares no
// AllowedIPs: everything. It is spelled out here because the overlap check has
// to reason about the same default the generated config uses — an endpoint with
// an empty field routes the whole internet, and two of those on one machine
// cannot coexist.
const DefaultAllowedIPs = "0.0.0.0/0"

// ParseAllowedIPs parses a WireGuard AllowedIPs list ("10.0.0.0/8, 192.168.1.5")
// into prefixes. A bare address is taken as a host route, as WireGuard does.
// Host bits are masked off, again like WireGuard: 10.0.0.1/8 means 10.0.0.0/8.
func ParseAllowedIPs(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			pfx, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, fmt.Errorf("%q is not a valid network (expected something like 10.0.0.0/8)", part)
			}
			out = append(out, pfx.Masked())
			continue
		}
		addr, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("%q is not a valid address or network", part)
		}
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return out, nil
}

// AllowedIPsOr parses an endpoint's AllowedIPs, substituting the default when it
// is empty — the same substitution ClientConfig makes when generating the peer.
func AllowedIPsOr(list string) ([]netip.Prefix, error) {
	if strings.TrimSpace(list) == "" {
		list = DefaultAllowedIPs
	}
	return ParseAllowedIPs(list)
}

// Overlap returns the first pair of prefixes from a and b that cover a common
// address, if any.
//
// This is not a style question. A WireGuard interface routes each allowed IP to
// exactly one peer: when a machine is linked to two endpoints whose AllowedIPs
// intersect, the config is accepted but the overlapping routes silently end up
// on whichever peer was configured last, and the other tunnel never receives
// that traffic. Two endpoints that both default to 0.0.0.0/0 are the common
// case, and the symptom (one site unreachable, at random) is miserable to chase.
func Overlap(a, b []netip.Prefix) (netip.Prefix, netip.Prefix, bool) {
	for _, x := range a {
		for _, y := range b {
			if x.Overlaps(y) {
				return x, y, true
			}
		}
	}
	return netip.Prefix{}, netip.Prefix{}, false
}
