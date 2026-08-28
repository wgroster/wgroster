package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// write puts a YAML document in a temp file and returns its path.
func write(t *testing.T, yaml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// minimal is a configuration that loads cleanly: one auth source and a strong
// session key. Tests append or override fields on top of it.
const minimal = `
session_key: "0123456789abcdef0123456789abcdef"
local_admin:
  username: admin
  password_hash: "$2a$10$abcdefghijklmnopqrstuv"
`

func load(t *testing.T, yaml string) (*Config, error) {
	t.Helper()
	// A key in the environment would override what the document declares.
	t.Setenv("WG_SESSION_KEY", "")
	return Load(write(t, yaml))
}

func TestLoadDefaults(t *testing.T) {
	c, err := load(t, minimal)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Listen != ":8080" || c.VPNCIDR != "10.0.0.0/16" {
		t.Errorf("defaults not applied: listen %q, vpn_cidr %q", c.Listen, c.VPNCIDR)
	}
	if c.LDAP.MemberAttr != "memberUid" || c.LDAP.PhotoAttr != "jpegPhoto" {
		t.Errorf("LDAP defaults not applied: %+v", c.LDAP)
	}
	if c.SessionTTL != 12*time.Hour || c.SessionMaxLifetime != 7*24*time.Hour {
		t.Errorf("session defaults = %s / %s", c.SessionTTL, c.SessionMaxLifetime)
	}
}

func TestLoadRejects(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string // substring of the expected error
	}{
		{
			// A short key would let an attacker brute-force session signatures.
			name: "short session key",
			yaml: "session_key: short\nlocal_admin:\n  username: admin\n  password: x\n",
			want: "session_key is too short",
		},
		{
			name: "no auth source",
			yaml: `session_key: "0123456789abcdef0123456789abcdef"` + "\n",
			want: "no authentication configured",
		},
		{
			name: "local admin without password",
			yaml: "session_key: \"0123456789abcdef0123456789abcdef\"\nlocal_admin:\n  username: admin\n",
			want: "no password or password_hash",
		},
		{
			name: "empty vpn_cidr",
			yaml: minimal + "vpn_cidr: \"\"\n",
			want: "vpn_cidr is required",
		},
		{
			name: "unparseable session_ttl",
			yaml: minimal + "session_ttl: 7d\n",
			want: "invalid session_ttl",
		},
		{
			name: "negative session_ttl",
			yaml: minimal + "session_ttl: -1h\n",
			want: "session_ttl must be positive",
		},
		{
			// The absolute cap must not undercut the sliding lifetime.
			name: "max lifetime below ttl",
			yaml: minimal + "session_ttl: 48h\nsession_max_lifetime: 12h\n",
			want: "must be >= session_ttl",
		},
		{
			name: "self enroll without endpoint",
			yaml: minimal + "self_enroll: true\n",
			want: "self_enroll requires self_enroll_endpoint",
		},
		{
			name: "negative audit retention",
			yaml: minimal + "audit_retention_days: -1\n",
			want: "audit_retention_days must not be negative",
		},
		{
			name: "negative pending expiry",
			yaml: minimal + "pending_expiry_days: -3\n",
			want: "pending_expiry_days must not be negative",
		},
		{
			name: "malformed yaml",
			yaml: "session_key: [unterminated\n",
			want: "parse config",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := load(t, tc.yaml)
			if err == nil {
				t.Fatalf("expected an error mentioning %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	t.Setenv("WG_SESSION_KEY", "")
	if _, err := Load(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestSessionKeyEnvOverridesAndEphemeralFallback(t *testing.T) {
	// The environment wins over the document.
	t.Setenv("WG_SESSION_KEY", "fedcba9876543210fedcba9876543210")
	c, err := Load(write(t, minimal))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.SessionKey != "fedcba9876543210fedcba9876543210" {
		t.Errorf("session key = %q, want the environment value", c.SessionKey)
	}

	// With no key at all one is generated rather than left empty.
	t.Setenv("WG_SESSION_KEY", "")
	c, err = Load(write(t, "local_admin:\n  username: admin\n  password: x\n"))
	if err != nil {
		t.Fatalf("Load without a key: %v", err)
	}
	if len(c.SessionKey) < minSessionKeyLen {
		t.Errorf("generated session key is %d bytes, want >= %d", len(c.SessionKey), minSessionKeyLen)
	}
}

func TestLDAPConfigured(t *testing.T) {
	cases := []struct {
		ldap LDAP
		want bool
	}{
		{LDAP{}, false},
		{LDAP{URL: "ldap://x"}, false},
		{LDAP{BindDNPattern: "uid=%s,dc=x"}, false},
		{LDAP{URL: "ldap://x", BindDNPattern: "uid=%s,dc=x"}, true},
	}
	for _, tc := range cases {
		if got := tc.ldap.Configured(); got != tc.want {
			t.Errorf("Configured(%+v) = %v, want %v", tc.ldap, got, tc.want)
		}
	}
}

func TestLDAPOnlyIsEnoughAuth(t *testing.T) {
	c, err := load(t, `
session_key: "0123456789abcdef0123456789abcdef"
ldap:
  url: ldaps://ldap.example.com
  bind_dn_pattern: "uid=%s,ou=people,dc=example,dc=com"
`)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.LDAP.Configured() || c.LocalAdmin.Enabled() {
		t.Errorf("expected LDAP-only auth, got %+v / %+v", c.LDAP, c.LocalAdmin)
	}
}

func TestOrphanCheckDefaults(t *testing.T) {
	c, err := load(t, minimal)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.OrphanAction != OrphanFlag {
		t.Errorf("orphan_action = %q, want %q by default", c.OrphanAction, OrphanFlag)
	}
	// Off unless a grace period is set: the check must never start on its own.
	if c.OrphanCheckEnabled() {
		t.Error("the offboarding check is enabled without orphan_grace_days")
	}
}

func TestOrphanCheckRequiresLDAP(t *testing.T) {
	// The check asks the directory whether a uid still exists, so local_admin
	// alone cannot answer it. Fail loudly rather than never run.
	_, err := load(t, minimal+"\norphan_grace_days: 7\n")
	if err == nil || !strings.Contains(err.Error(), "requires LDAP") {
		t.Fatalf("err = %v, want it to say LDAP is required", err)
	}
}

func TestOrphanCheckEnabledWithLDAP(t *testing.T) {
	c, err := load(t, minimal+`
orphan_grace_days: 7
orphan_action: disable
ldap:
  url: "ldap://ldap.example.com:389"
  bind_dn_pattern: "uid=%s,ou=people,dc=example,dc=com"
`)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.OrphanCheckEnabled() || c.OrphanAction != OrphanDisable {
		t.Errorf("enabled %v, action %q", c.OrphanCheckEnabled(), c.OrphanAction)
	}
}

func TestOrphanActionRejectsUnknownValue(t *testing.T) {
	_, err := load(t, minimal+"\norphan_action: delete\n")
	if err == nil || !strings.Contains(err.Error(), "invalid orphan_action") {
		t.Fatalf("err = %v, want an invalid orphan_action error", err)
	}
}

func TestOrphanGraceDaysRejectsNegative(t *testing.T) {
	_, err := load(t, minimal+"\norphan_grace_days: -1\n")
	if err == nil || !strings.Contains(err.Error(), "orphan_grace_days") {
		t.Fatalf("err = %v, want an orphan_grace_days error", err)
	}
}
