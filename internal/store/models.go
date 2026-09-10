package store

import "time"

// Machine status values.
const (
	StatusPending = "pending"
	StatusActive  = "active"
)

// Endpoint is a VPN concentrator declared by an administrator.
type Endpoint struct {
	ID                  int64
	Name                string
	PublicKey           string
	HostPort            string // public endpoint, e.g. "vpn-par.example.com:51820"
	AllowedIPs          string // networks reachable behind this endpoint
	DNS                 string
	MTU                 int
	PersistentKeepalive int
	TunnelIP            string // informational: the hub's own tunnel address
	UploadToken         string // bearer token for status uploads
	CreatedAt           time.Time
}

// Machine is a user device with a single global VPN address and one or more
// endpoints it connects to.
type Machine struct {
	ID         int64
	OwnerUID   string
	OwnerName  string // display name (LDAP cn) of the owner, may be empty
	Name       string
	PublicKey  string
	Address    string // single global tunnel IP, e.g. "10.0.0.5"
	Status     string
	Icon       string // device icon, one of MachineIcons
	CreatedAt  time.Time
	ApprovedAt *time.Time
	ApprovedBy string
}

// MachineIcons is the fixed set of device icons a machine may carry, in the
// order the pickers offer them. Keeping it small and closed means the value is
// a safe lookup key everywhere it is rendered.
var MachineIcons = []string{"laptop", "phone", "tablet", "server", "desktop"}

// DefaultMachineIcon is what a machine gets when none was chosen, and what rows
// predating the column hold.
const DefaultMachineIcon = "desktop"

// NormalizeIcon maps a submitted icon onto the known set. An unrecognised value
// is a stale form or a hand-crafted POST, not something worth refusing a machine
// over, so it falls back to the default instead of erroring.
func NormalizeIcon(icon string) string {
	for _, v := range MachineIcons {
		if v == icon {
			return v
		}
	}
	return DefaultMachineIcon
}

// OwnerDisplay returns the owner's display name, falling back to the uid.
func (m *Machine) OwnerDisplay() string {
	if m.OwnerName != "" {
		return m.OwnerName
	}
	return m.OwnerUID
}

// StatusPeer is a single peer line parsed from an uploaded "wg show dump".
type StatusPeer struct {
	EndpointID     int64
	PublicKey      string
	LastHandshake  time.Time
	RX             int64
	TX             int64
	RemoteEndpoint string
	AllowedIPs     string // allowed-ips as seen by the hub (server side)
}
