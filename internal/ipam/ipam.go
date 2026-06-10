// Package ipam handles allocation and validation of client addresses within the
// global VPN address pool.
package ipam

import (
	"fmt"
	"net/netip"
)

// Pool represents the global client address space.
type Pool struct {
	prefix netip.Prefix
}

// New parses a CIDR such as "10.0.0.0/16".
func New(cidr string) (*Pool, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid vpn_cidr %q: %w", cidr, err)
	}
	return &Pool{prefix: p.Masked()}, nil
}

// CIDR returns the pool prefix as a string.
func (p *Pool) CIDR() string { return p.prefix.String() }

// Contains reports whether addr (a bare IP, no prefix) is inside the pool.
func (p *Pool) Contains(addr string) bool {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	return p.prefix.Contains(a)
}

// Validate checks that addr is a usable client address: a bare IP within the
// pool, not equal to the network or broadcast address.
func (p *Pool) Validate(addr string, used []string) error {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return fmt.Errorf("%q is not a valid IP address", addr)
	}
	if !p.prefix.Contains(a) {
		return fmt.Errorf("%s is outside the VPN range %s", addr, p.prefix)
	}
	if a == p.prefix.Addr() {
		return fmt.Errorf("%s is the network address", addr)
	}
	if bc := p.broadcast(); bc.IsValid() && a == bc {
		return fmt.Errorf("%s is the broadcast address", addr)
	}
	for _, u := range used {
		if u == addr {
			return fmt.Errorf("%s is already assigned", addr)
		}
	}
	return nil
}

// broadcast returns the last (broadcast) address of an IPv4 prefix, or the
// zero Addr when the concept does not apply (IPv6, or a /31 or /32 where every
// address is usable).
func (p *Pool) broadcast() netip.Addr {
	if !p.prefix.Addr().Is4() || p.prefix.Bits() >= 31 {
		return netip.Addr{}
	}
	b := p.prefix.Masked().Addr().As4()
	host := uint32(32 - p.prefix.Bits())
	mask := uint32(1)<<host - 1 // host bits set to 1
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= mask
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// NextFree returns the lowest address in the pool not present in used. The
// network and broadcast addresses are skipped.
func (p *Pool) NextFree(used []string) (string, error) {
	taken := make(map[netip.Addr]bool, len(used))
	for _, u := range used {
		if a, err := netip.ParseAddr(u); err == nil {
			taken[a] = true
		}
	}
	bc := p.broadcast()
	// Start at network address + 1.
	a := p.prefix.Addr().Next()
	for p.prefix.Contains(a) {
		if a == bc {
			break // reached the broadcast address: pool exhausted
		}
		if !taken[a] {
			return a.String(), nil
		}
		a = a.Next()
	}
	return "", fmt.Errorf("no free address left in %s", p.prefix)
}
