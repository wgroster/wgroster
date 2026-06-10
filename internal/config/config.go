// Package config loads the application configuration from a YAML file.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// minSessionKeyLen is the minimum accepted length (in bytes) for an
// operator-supplied session_key. Sessions are HMAC-signed with it.
const minSessionKeyLen = 32

// Config holds the full application configuration.
type Config struct {
	// Listen is the HTTP listen address, e.g. ":8080".
	Listen string `yaml:"listen"`
	// BaseURL is the externally reachable base URL, used in docs shown to users.
	BaseURL string `yaml:"base_url"`
	// SessionKey signs the session cookies. Keep it secret and stable.
	SessionKey string `yaml:"session_key"`
	// CookieSecure sets the Secure flag on cookies (enable behind HTTPS).
	CookieSecure bool `yaml:"cookie_secure"`
	// SessionTTLRaw is the sliding session lifetime, e.g. "12h", "30m", "7d" is
	// not valid (use "168h"). Parsed into SessionTTL. Default 12h.
	SessionTTLRaw string `yaml:"session_ttl"`
	// SessionTTL is the parsed session lifetime (sliding: extended on activity).
	SessionTTL time.Duration `yaml:"-"`
	// SessionMaxLifetimeRaw is the absolute lifetime cap: a session is rejected
	// once it is older than this, regardless of sliding refreshes. Must be >=
	// session_ttl. Parsed into SessionMaxLifetime. Default 168h (7 days).
	SessionMaxLifetimeRaw string `yaml:"session_max_lifetime"`
	// SessionMaxLifetime is the parsed absolute session lifetime cap.
	SessionMaxLifetime time.Duration `yaml:"-"`
	// Database is the path to the SQLite file.
	Database string `yaml:"database"`
	// VPNCIDR is the global client address pool, e.g. "10.0.0.0/16".
	VPNCIDR string `yaml:"vpn_cidr"`
	// MetricsToken, when set, lets Prometheus scrape /metrics with a matching
	// bearer token. /metrics is never public: without a token only an
	// authenticated admin session may read it.
	MetricsToken string `yaml:"metrics_token"`
	// AlertWebhookURL, when set, receives a JSON POST when an endpoint goes
	// stale or a drift (missing/unexpected/mismatch) appears or clears.
	AlertWebhookURL string `yaml:"alert_webhook_url"`
	// GeoIPCityDB / GeoIPASNDB are optional paths to local MaxMind GeoLite2
	// databases (City and ASN). When set, the peer drawer shows country/city/ASN
	// of the remote IP — looked up locally, no external call.
	GeoIPCityDB string `yaml:"geoip_db"`
	GeoIPASNDB  string `yaml:"geoip_asn_db"`
	// TrustedProxy enables reading the client IP from X-Forwarded-For. Enable
	// ONLY when the portal is behind a reverse proxy that sets/overwrites that
	// header, otherwise clients could spoof their IP.
	TrustedProxy bool `yaml:"trusted_proxy"`
	// LDAP holds the directory configuration.
	LDAP LDAP `yaml:"ldap"`
	// LocalAdmin is an optional built-in administrator account, useful for
	// bootstrap and testing without an LDAP server. Disabled when empty.
	LocalAdmin LocalAdmin `yaml:"local_admin"`

	// SelfEnroll lets a logged-in user register a device that reserves an IP
	// immediately (so a complete config/QR is built client-side on the spot);
	// the machine stays pending until an admin approves it. Off by default.
	SelfEnroll bool `yaml:"self_enroll"`
	// SelfEnrollEndpoint is the endpoint name used to build self-enrolled
	// configs (required when self_enroll is on).
	SelfEnrollEndpoint string `yaml:"self_enroll_endpoint"`
	// MaxPendingPerUser caps pending machines per user (0 = unlimited).
	MaxPendingPerUser int `yaml:"max_pending_per_user"`
	// PendingExpiryDays auto-deletes pending machines older than N days,
	// freeing their reserved IP (0 = never).
	PendingExpiryDays int `yaml:"pending_expiry_days"`
}

// LocalAdmin is a built-in administrator account checked before LDAP.
type LocalAdmin struct {
	// Username enables the account when non-empty.
	Username string `yaml:"username"`
	// PasswordHash is a bcrypt hash (recommended). Generate it with
	// "wgroster -hash-password".
	PasswordHash string `yaml:"password_hash"`
	// Password is a clear-text password (development convenience only). Ignored
	// when PasswordHash is set.
	Password string `yaml:"password"`
}

// Enabled reports whether the local admin account is configured.
func (l LocalAdmin) Enabled() bool { return l.Username != "" }

// Configured reports whether the LDAP directory is usable for authentication.
func (l LDAP) Configured() bool { return l.URL != "" && l.BindDNPattern != "" }

// LDAP holds the OpenLDAP connection and group-resolution settings.
type LDAP struct {
	// URL is the server URL, e.g. "ldap://ldap.example.com:389".
	URL string `yaml:"url"`
	// BindDNPattern builds a user DN from the login, e.g.
	// "uid=%s,ou=people,dc=example,dc=com".
	BindDNPattern string `yaml:"bind_dn_pattern"`
	// AdminGroupDN is the group whose members are administrators.
	AdminGroupDN string `yaml:"admin_group_dn"`
	// MemberAttr is the attribute listing group members. For OpenLDAP this is
	// usually "memberUid" (value = uid) or "member" (value = full user DN).
	MemberAttr string `yaml:"member_attr"`
	// NameAttr is the attribute holding the user's display name (default "cn";
	// Active Directory often uses "displayName").
	NameAttr string `yaml:"name_attr"`
	// SearchBindDN / SearchBindPassword is an optional service account used to
	// read group membership. If empty, the user's own connection is used.
	SearchBindDN       string `yaml:"search_bind_dn"`
	SearchBindPassword string `yaml:"search_bind_password"`
	// StartTLS upgrades a plain ldap:// connection to TLS.
	StartTLS bool `yaml:"start_tls"`
	// InsecureSkipVerify disables TLS certificate verification (testing only).
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
}

// Load reads and validates the configuration from path. The session key may be
// overridden by the WG_SESSION_KEY environment variable; if none is provided an
// ephemeral key is generated (sessions then reset on restart).
func Load(path string) (*Config, error) {
	c := &Config{
		Listen:   ":8080",
		Database: "/data/wgroster.db",
		VPNCIDR:  "10.0.0.0/16",
		LDAP: LDAP{
			MemberAttr: "memberUid",
		},
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if v := os.Getenv("WG_SESSION_KEY"); v != "" {
		c.SessionKey = v
	}
	if c.SessionKey == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		c.SessionKey = hex.EncodeToString(b)
		fmt.Fprintln(os.Stderr, "WARN: no session_key configured; generated an ephemeral one (sessions reset on restart)")
	} else if len(c.SessionKey) < minSessionKeyLen {
		// Sessions are HMAC-signed with this key; a weak key lets an attacker
		// forge admin sessions offline. Fail closed rather than warn.
		return nil, fmt.Errorf("session_key is too short (%d bytes); use at least %d bytes of random data, e.g. `openssl rand -hex 32`", len(c.SessionKey), minSessionKeyLen)
	}

	if !c.CookieSecure {
		fmt.Fprintln(os.Stderr, "WARN: cookie_secure is false; session cookies are sent over plain HTTP and can be captured. Enable it behind HTTPS.")
	}

	if c.VPNCIDR == "" {
		return nil, fmt.Errorf("vpn_cidr is required")
	}

	c.SessionTTL = 12 * time.Hour
	if c.SessionTTLRaw != "" {
		d, err := time.ParseDuration(c.SessionTTLRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid session_ttl %q: %w", c.SessionTTLRaw, err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("session_ttl must be positive")
		}
		c.SessionTTL = d
	}

	c.SessionMaxLifetime = 7 * 24 * time.Hour
	if c.SessionMaxLifetimeRaw != "" {
		d, err := time.ParseDuration(c.SessionMaxLifetimeRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid session_max_lifetime %q: %w", c.SessionMaxLifetimeRaw, err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("session_max_lifetime must be positive")
		}
		c.SessionMaxLifetime = d
	}
	if c.SessionMaxLifetime < c.SessionTTL {
		return nil, fmt.Errorf("session_max_lifetime (%s) must be >= session_ttl (%s)", c.SessionMaxLifetime, c.SessionTTL)
	}

	if c.LocalAdmin.Enabled() && c.LocalAdmin.PasswordHash == "" && c.LocalAdmin.Password == "" {
		return nil, fmt.Errorf("local_admin.username is set but no password or password_hash provided")
	}
	if c.LocalAdmin.Enabled() && c.LocalAdmin.PasswordHash == "" && c.LocalAdmin.Password != "" {
		fmt.Fprintln(os.Stderr, "WARN: local_admin uses a clear-text password; set password_hash (wgroster -hash-password) outside of development")
	}

	// At least one authentication source must be usable.
	if !c.LDAP.Configured() && !c.LocalAdmin.Enabled() {
		return nil, fmt.Errorf("no authentication configured: set ldap.url + ldap.bind_dn_pattern, or local_admin")
	}

	if c.LDAP.Configured() && !strings.HasPrefix(strings.ToLower(c.LDAP.URL), "ldaps://") && !c.LDAP.StartTLS {
		fmt.Fprintln(os.Stderr, "WARN: LDAP is configured without TLS; bind credentials (including user passwords) cross the network in clear text. Use an ldaps:// URL or set ldap.start_tls.")
	}

	if c.SelfEnroll && c.SelfEnrollEndpoint == "" {
		return nil, fmt.Errorf("self_enroll requires self_enroll_endpoint (the endpoint name to enroll into)")
	}
	return c, nil
}
