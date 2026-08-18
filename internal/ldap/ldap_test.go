package ldap

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/wgroster/wgroster/internal/config"
)

const (
	peoplePattern = "uid=%s,ou=people,dc=example,dc=com"
	aliceDN       = "uid=alice,ou=people,dc=example,dc=com"
	bobDN         = "uid=bob,ou=people,dc=example,dc=com"
	groupDN       = "cn=vpn-admins,ou=groups,dc=example,dc=com"
	serviceDN     = "cn=svc,dc=example,dc=com"
)

// photo is deliberately not valid UTF-8: a real jpegPhoto is binary, and it must
// survive the round trip byte for byte.
var photo = []byte{0xff, 0xd8, 0xff, 0x00, 0x01, 0x7f}

// seeded returns a directory holding alice (an admin), bob (not an admin) and
// the admin group, listing members both by uid and by DN.
func seeded(t *testing.T) *fakeDir {
	d := newFakeDir(t)
	d.passwords[aliceDN] = "s3cret"
	d.passwords[bobDN] = "hunter2"
	d.passwords[serviceDN] = "svcpass"
	d.entries[aliceDN] = map[string][]string{
		"cn":          {"Alice Example"},
		"displayName": {"Alice from the directory"},
		"jpegPhoto":   {string(photo)},
	}
	d.entries[bobDN] = map[string][]string{"cn": {"Bob Example"}}
	d.entries[groupDN] = map[string][]string{
		"memberUid": {"alice", "carol"},
		"member":    {aliceDN},
	}
	return d
}

func baseCfg(d *fakeDir) config.LDAP {
	return config.LDAP{
		URL:           d.url(),
		BindDNPattern: peoplePattern,
		AdminGroupDN:  groupDN,
		MemberAttr:    "memberUid",
		PhotoAttr:     "jpegPhoto",
	}
}

func TestAuthenticateAdmin(t *testing.T) {
	d := seeded(t)
	name, gotPhoto, isAdmin, err := New(baseCfg(d)).Authenticate("alice", "s3cret")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if name != "Alice Example" {
		t.Errorf("name = %q, want %q", name, "Alice Example")
	}
	if !bytes.Equal(gotPhoto, photo) {
		t.Errorf("photo = %v, want %v", gotPhoto, photo)
	}
	if !isAdmin {
		t.Error("isAdmin = false, want true for a member of the admin group")
	}

	// The user's own credentials are used, and the lookups reuse that connection.
	binds := d.bindLog()
	if len(binds) != 1 || binds[0].dn != aliceDN || binds[0].password != "s3cret" {
		t.Fatalf("binds = %+v", binds)
	}
	if n := d.connCount(); n != 1 {
		t.Errorf("opened %d connections, want 1 without a service account", n)
	}
	searches := d.searchLog()
	if len(searches) != 2 {
		t.Fatalf("searches = %+v, want a profile read then a group check", searches)
	}
	if searches[0].base != aliceDN || !searches[0].present {
		t.Errorf("profile search = %+v", searches[0])
	}
	if searches[1].base != groupDN || searches[1].filterAttr != "memberUid" || searches[1].filterValue != "alice" {
		t.Errorf("group search = %+v, want memberUid=alice on the group", searches[1])
	}
}

func TestAuthenticateNonAdmin(t *testing.T) {
	d := seeded(t)
	name, _, isAdmin, err := New(baseCfg(d)).Authenticate("bob", "hunter2")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if name != "Bob Example" {
		t.Errorf("name = %q", name)
	}
	if isAdmin {
		t.Error("isAdmin = true for a user absent from the group")
	}
}

func TestAuthenticateRejectsBadCredentials(t *testing.T) {
	d := seeded(t)
	a := New(baseCfg(d))

	if _, _, _, err := a.Authenticate("alice", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong password: err = %v, want ErrInvalidCredentials", err)
	}
	if _, _, _, err := a.Authenticate("ghost", "whatever"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("unknown user: err = %v, want ErrInvalidCredentials", err)
	}

	// An empty password must be refused locally: an anonymous bind succeeds on
	// many directories, which would turn a blank form into a valid login.
	before := d.connCount()
	if _, _, _, err := a.Authenticate("alice", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("empty password: err = %v, want ErrInvalidCredentials", err)
	}
	if d.connCount() != before {
		t.Error("an empty password reached the directory instead of being refused locally")
	}
}

// With member_attr other than memberUid the group is expected to list full DNs,
// so the filter must carry the user's DN rather than the bare uid.
func TestAuthenticateMemberAttrUsesDN(t *testing.T) {
	d := seeded(t)
	cfg := baseCfg(d)
	cfg.MemberAttr = "member"
	_, _, isAdmin, err := New(cfg).Authenticate("alice", "s3cret")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !isAdmin {
		t.Error("isAdmin = false, want true via the member attribute")
	}
	searches := d.searchLog()
	last := searches[len(searches)-1]
	if last.filterAttr != "member" || last.filterValue != aliceDN {
		t.Errorf("group search = %+v, want member=%s", last, aliceDN)
	}
}

// A login is interpolated into the bind DN pattern, so DN metacharacters must be
// escaped rather than allowed to restructure the DN.
func TestAuthenticateEscapesUID(t *testing.T) {
	d := seeded(t)
	if _, _, _, err := New(baseCfg(d)).Authenticate(`al,ice+x`, "s3cret"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials for an unknown user", err)
	}
	binds := d.bindLog()
	if len(binds) != 1 {
		t.Fatalf("binds = %+v", binds)
	}
	if !strings.HasPrefix(binds[0].dn, `uid=al\,ice\+x,ou=people,`) {
		t.Errorf("bind DN = %q, want the uid escaped", binds[0].dn)
	}
}

func TestAuthenticateCustomAttributes(t *testing.T) {
	d := seeded(t)
	cfg := baseCfg(d)
	cfg.NameAttr = "displayName"
	cfg.PhotoAttr = "" // photo lookups disabled
	name, gotPhoto, _, err := New(cfg).Authenticate("alice", "s3cret")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if name != "Alice from the directory" {
		t.Errorf("name = %q, want the displayName value", name)
	}
	if len(gotPhoto) != 0 {
		t.Errorf("photo = %v, want none when photo_attr is empty", gotPhoto)
	}
	profile := d.searchLog()[0]
	if len(profile.attrs) != 1 || profile.attrs[0] != "displayName" {
		t.Errorf("requested attributes = %v, want [displayName] only", profile.attrs)
	}
}

// A directory that cannot serve the profile must not block the login: the name
// and photo are best-effort, membership is not.
func TestAuthenticateProfileFailureStillLogsIn(t *testing.T) {
	d := seeded(t)
	delete(d.entries, aliceDN) // profile read now answers noSuchObject
	name, gotPhoto, isAdmin, err := New(baseCfg(d)).Authenticate("alice", "s3cret")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if name != "" || len(gotPhoto) != 0 {
		t.Errorf("name/photo = %q/%v, want empty", name, gotPhoto)
	}
	if !isAdmin {
		t.Error("isAdmin = false: membership must still be resolved")
	}
}

// An entry that exists but yields no result is "known empty", not a failure.
func TestAuthenticateEmptyProfileResult(t *testing.T) {
	d := seeded(t)
	d.emptyFor[aliceDN] = true
	name, _, _, err := New(baseCfg(d)).Authenticate("alice", "s3cret")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if name != "" {
		t.Errorf("name = %q, want empty", name)
	}
}

func TestAuthenticateWithoutAdminGroup(t *testing.T) {
	d := seeded(t)
	cfg := baseCfg(d)
	cfg.AdminGroupDN = ""
	_, _, isAdmin, err := New(cfg).Authenticate("alice", "s3cret")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if isAdmin {
		t.Error("isAdmin = true with no admin group configured")
	}
	for _, s := range d.searchLog() {
		if s.base == groupDN {
			t.Errorf("group was searched anyway: %+v", s)
		}
	}
}

// With a service account, lookups must run on its own connection — the point
// being that the user's rights are not what resolves membership.
func TestAuthenticateUsesServiceAccount(t *testing.T) {
	d := seeded(t)
	cfg := baseCfg(d)
	cfg.SearchBindDN = serviceDN
	cfg.SearchBindPassword = "svcpass"

	if _, _, isAdmin, err := New(cfg).Authenticate("alice", "s3cret"); err != nil || !isAdmin {
		t.Fatalf("Authenticate: isAdmin %v, err %v", isAdmin, err)
	}
	if n := d.connCount(); n != 2 {
		t.Errorf("opened %d connections, want 2 (user + service account)", n)
	}
	binds := d.bindLog()
	if len(binds) != 2 || binds[1].dn != serviceDN || binds[1].password != "svcpass" {
		t.Fatalf("binds = %+v", binds)
	}
	for _, s := range d.searchLog() {
		if s.conn != binds[1].conn {
			t.Errorf("search %+v ran on connection %d, want the service account's %d", s, s.conn, binds[1].conn)
		}
	}
}

func TestAuthenticateServiceAccountBindFailure(t *testing.T) {
	d := seeded(t)
	cfg := baseCfg(d)
	cfg.SearchBindDN = serviceDN
	cfg.SearchBindPassword = "wrong"

	_, _, _, err := New(cfg).Authenticate("alice", "s3cret")
	if err == nil {
		t.Fatal("expected an error when the service account cannot bind")
	}
	// The user's own credentials were fine, so this must not read as a bad login.
	if errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("err = %v, want a service-bind failure rather than ErrInvalidCredentials", err)
	}
	if !strings.Contains(err.Error(), "search bind") {
		t.Errorf("err = %v, want it to name the search bind", err)
	}
}

func TestAuthenticateUnreachableDirectory(t *testing.T) {
	cfg := config.LDAP{URL: closedPortURL(t), BindDNPattern: peoplePattern}
	_, _, _, err := New(cfg).Authenticate("alice", "s3cret")
	if err == nil {
		t.Fatal("expected a dial error")
	}
	if errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("err = %v, want a transport error rather than ErrInvalidCredentials", err)
	}
}

func TestLookupProfileAnonymous(t *testing.T) {
	d := seeded(t)
	name, gotPhoto, err := New(baseCfg(d)).LookupProfile("alice")
	if err != nil {
		t.Fatalf("LookupProfile: %v", err)
	}
	if name != "Alice Example" || !bytes.Equal(gotPhoto, photo) {
		t.Errorf("got %q / %v", name, gotPhoto)
	}
	// No service account: the read is attempted anonymously, i.e. with no bind.
	if binds := d.bindLog(); len(binds) != 0 {
		t.Errorf("binds = %+v, want none for an anonymous lookup", binds)
	}
}

func TestLookupProfileWithServiceAccount(t *testing.T) {
	d := seeded(t)
	cfg := baseCfg(d)
	cfg.SearchBindDN = serviceDN
	cfg.SearchBindPassword = "svcpass"

	name, _, err := New(cfg).LookupProfile("alice")
	if err != nil {
		t.Fatalf("LookupProfile: %v", err)
	}
	if name != "Alice Example" {
		t.Errorf("name = %q", name)
	}
	binds := d.bindLog()
	if len(binds) != 1 || binds[0].dn != serviceDN {
		t.Errorf("binds = %+v, want a single service-account bind", binds)
	}
}

func TestLookupProfileUnconfigured(t *testing.T) {
	if _, _, err := New(config.LDAP{}).LookupProfile("alice"); !errors.Is(err, ErrProfileUnavailable) {
		t.Errorf("err = %v, want ErrProfileUnavailable", err)
	}
}

func TestLookupProfileAbsentEntry(t *testing.T) {
	d := seeded(t)
	// A missing entry is a directory error, which the caller uses to avoid
	// caching an empty profile.
	if _, _, err := New(baseCfg(d)).LookupProfile("ghost"); err == nil {
		t.Error("expected an error for an absent entry")
	}
	// An entry that yields no result is cacheable as "known empty".
	d.emptyFor[aliceDN] = true
	name, gotPhoto, err := New(baseCfg(d)).LookupProfile("alice")
	if err != nil || name != "" || len(gotPhoto) != 0 {
		t.Errorf("got %q / %v, err %v, want empty and no error", name, gotPhoto, err)
	}
}

func TestStartTLS(t *testing.T) {
	d := seeded(t)
	d.startTLS = true
	d.cert = selfSignedCert(t)

	cfg := baseCfg(d)
	cfg.StartTLS = true
	cfg.InsecureSkipVerify = true
	name, _, isAdmin, err := New(cfg).Authenticate("alice", "s3cret")
	if err != nil {
		t.Fatalf("Authenticate over StartTLS: %v", err)
	}
	if name != "Alice Example" || !isAdmin {
		t.Errorf("got %q / admin %v over StartTLS", name, isAdmin)
	}

	// The certificate is self-signed, so verification must fail once it is on.
	cfg.InsecureSkipVerify = false
	if _, _, _, err := New(cfg).Authenticate("alice", "s3cret"); err == nil {
		t.Error("expected certificate verification to fail without insecure_skip_verify")
	}
}

func TestStartTLSRefusedByDirectory(t *testing.T) {
	d := seeded(t) // startTLS stays false
	cfg := baseCfg(d)
	cfg.StartTLS = true

	_, _, _, err := New(cfg).Authenticate("alice", "s3cret")
	if err == nil {
		t.Fatal("expected an error when the directory refuses StartTLS")
	}
	if !strings.Contains(err.Error(), "starttls") {
		t.Errorf("err = %v, want it to name the failed StartTLS", err)
	}
	if binds := d.bindLog(); len(binds) != 0 {
		t.Errorf("credentials were sent over the unencrypted connection: %+v", binds)
	}
}

func TestProfileLookupEnabled(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.LDAP
		want bool
	}{
		{"unconfigured", config.LDAP{}, false},
		{"url only", config.LDAP{URL: "ldap://x"}, false},
		{"pattern only", config.LDAP{BindDNPattern: peoplePattern}, false},
		{"configured, anonymous reads", config.LDAP{URL: "ldap://x", BindDNPattern: peoplePattern}, true},
		{"configured with service account", config.LDAP{URL: "ldap://x", BindDNPattern: peoplePattern, SearchBindDN: serviceDN}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := New(tc.cfg).ProfileLookupEnabled(); got != tc.want {
				t.Errorf("ProfileLookupEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

// The fake directory is only useful if it behaves like one, so check the pieces
// the assertions above depend on.
func TestFakeDirectorySanity(t *testing.T) {
	d := seeded(t)
	if got := fmt.Sprintf(peoplePattern, "alice"); got != aliceDN {
		t.Fatalf("pattern renders %q, want %q", got, aliceDN)
	}
	if _, _, _, err := New(baseCfg(d)).Authenticate("alice", "s3cret"); err != nil {
		t.Fatalf("baseline login failed: %v", err)
	}
}
