// Package wg generates client configurations and parses "wg show" dumps.
package wg

import (
	"fmt"
	"net"
	"strings"

	"github.com/wgroster/wgroster/internal/store"
)

// ClientConfig renders a complete WireGuard client configuration for a machine
// and its linked endpoints. The private key is never known to the portal, so a
// placeholder is emitted for the user to fill in.
func ClientConfig(m *store.Machine, endpoints []*store.Endpoint) string {
	var b strings.Builder

	address := m.Address
	if address != "" && !strings.Contains(address, "/") {
		address += "/32"
	}

	b.WriteString("[Interface]\n")
	b.WriteString("# Replace with the private key generated on this machine\n")
	b.WriteString("PrivateKey = <YOUR_PRIVATE_KEY>\n")
	b.WriteString(fmt.Sprintf("Address = %s\n", address))

	// DNS and MTU are taken from the first endpoint that defines them, since the
	// [Interface] section is shared across peers.
	for _, e := range endpoints {
		if e.DNS != "" {
			b.WriteString(fmt.Sprintf("DNS = %s\n", e.DNS))
			break
		}
	}
	for _, e := range endpoints {
		if e.MTU > 0 {
			b.WriteString(fmt.Sprintf("MTU = %d\n", e.MTU))
			break
		}
	}

	for _, e := range endpoints {
		b.WriteString("\n[Peer]\n")
		b.WriteString(fmt.Sprintf("# %s\n", e.Name))
		b.WriteString(fmt.Sprintf("PublicKey = %s\n", e.PublicKey))
		b.WriteString(fmt.Sprintf("Endpoint = %s\n", e.HostPort))
		allowed := e.AllowedIPs
		if allowed == "" {
			allowed = "0.0.0.0/0"
		}
		b.WriteString(fmt.Sprintf("AllowedIPs = %s\n", allowed))
		if e.PersistentKeepalive > 0 {
			b.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", e.PersistentKeepalive))
		}
	}

	return b.String()
}

// ConcentratorConfig renders the WireGuard configuration for the endpoint (hub)
// itself: an [Interface] section for the concentrator plus one [Peer] per
// machine currently expected to connect. The concentrator's private key is
// never known to the portal, so a placeholder is emitted for the operator to
// fill in. Names are validated (no control characters) at every write path, so
// they are safe to emit directly on comment lines.
func ConcentratorConfig(e *store.Endpoint, machines []*store.Machine) string {
	var b strings.Builder

	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("# %s concentrator\n", e.Name))
	b.WriteString("# Replace with the concentrator's private key\n")
	b.WriteString("PrivateKey = <CONCENTRATOR_PRIVATE_KEY>\n")
	if e.TunnelIP != "" {
		addr := e.TunnelIP
		if !strings.Contains(addr, "/") {
			addr += "/32"
		}
		b.WriteString(fmt.Sprintf("Address = %s\n", addr))
	}
	if _, port, err := net.SplitHostPort(e.HostPort); err == nil && port != "" {
		b.WriteString(fmt.Sprintf("ListenPort = %s\n", port))
	}
	if e.MTU > 0 {
		b.WriteString(fmt.Sprintf("MTU = %d\n", e.MTU))
	}

	for _, m := range machines {
		addr := m.Address
		if addr != "" && !strings.Contains(addr, "/") {
			addr += "/32"
		}
		b.WriteString("\n[Peer]\n")
		b.WriteString(fmt.Sprintf("# %s (%s)\n", m.Name, m.OwnerUID))
		b.WriteString(fmt.Sprintf("PublicKey = %s\n", m.PublicKey))
		b.WriteString(fmt.Sprintf("AllowedIPs = %s\n", addr))
	}

	return b.String()
}
