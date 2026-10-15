// Package ldap authenticates users against an OpenLDAP directory and resolves
// administrator membership from a group.
package ldap

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/wgroster/wgroster/internal/config"
)

// Authenticator binds users and checks admin-group membership.
type Authenticator struct {
	cfg config.LDAP
}

// New returns an Authenticator for the given configuration.
func New(cfg config.LDAP) *Authenticator { return &Authenticator{cfg: cfg} }

// ErrInvalidCredentials is returned when the bind fails.
var ErrInvalidCredentials = fmt.Errorf("invalid credentials")

func (a *Authenticator) dial() (*ldap.Conn, error) {
	conn, err := ldap.DialURL(a.cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("ldap dial: %w", err)
	}
	if a.cfg.StartTLS {
		tlsConf := &tls.Config{InsecureSkipVerify: a.cfg.InsecureSkipVerify}
		// go-ldap does not set ServerName for StartTLS, so certificate hostname
		// verification fails unless we derive it from the URL host.
		if u, err := url.Parse(a.cfg.URL); err == nil && u.Hostname() != "" {
			tlsConf.ServerName = u.Hostname()
		}
		if err := conn.StartTLS(tlsConf); err != nil {
			conn.Close()
			return nil, fmt.Errorf("ldap starttls: %w", err)
		}
	}
	return conn, nil
}

// ErrProfileUnavailable is returned by LookupProfile when the directory cannot
// be queried at all (LDAP not configured).
var ErrProfileUnavailable = fmt.Errorf("ldap not configured")

// Authenticate verifies the user's credentials and returns the user's login as
// the directory stores it, display name (cn), photo (may be nil) and whether the
// user is an administrator. The uid is the login typed on the form.
//
// The returned login is what the caller must use as the user's identity, not
// the typed one: directories match the login attribute case-insensitively and
// ignore surrounding spaces, so "alice", "Alice" and " alice" all bind as the
// same entry. Keying sessions and machines on the typed string would split one
// person into several owners (and several per-owner quotas). When the entry
// cannot be read back, the typed login, trimmed, is returned.
func (a *Authenticator) Authenticate(uid, password string) (canonUID, name string, photo []byte, isAdmin bool, err error) {
	if password == "" {
		return "", "", nil, false, ErrInvalidCredentials
	}
	uid = strings.TrimSpace(uid)
	conn, err := a.dial()
	if err != nil {
		return "", "", nil, false, err
	}
	defer conn.Close()

	userDN := fmt.Sprintf(a.cfg.BindDNPattern, ldap.EscapeDN(uid))
	if err := conn.Bind(userDN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return "", "", nil, false, ErrInvalidCredentials
		}
		return "", "", nil, false, fmt.Errorf("ldap bind: %w", err)
	}

	// Connection used for lookups: a service account when configured, otherwise
	// the user's own (already authenticated) connection.
	search := conn
	if a.cfg.SearchBindDN != "" {
		sc, err := a.dial()
		if err != nil {
			return "", "", nil, false, err
		}
		defer sc.Close()
		if err := sc.Bind(a.cfg.SearchBindDN, a.cfg.SearchBindPassword); err != nil {
			return "", "", nil, false, fmt.Errorf("ldap search bind: %w", err)
		}
		search = sc
	}

	// A failed profile read must not fail the login; treat name/photo as
	// best-effort, and keep the typed login when the stored one is unknown.
	stored, name, photo, _ := a.lookupProfile(search, userDN, a.loginAttr())
	canonUID = canonicalLogin(uid, stored)
	if canonUID != uid {
		userDN = fmt.Sprintf(a.cfg.BindDNPattern, ldap.EscapeDN(canonUID))
	}
	if a.cfg.AdminGroupDN != "" {
		isAdmin, err = a.isMember(search, canonUID, userDN)
		if err != nil {
			return "", "", nil, false, err
		}
	}
	return canonUID, name, photo, isAdmin, nil
}

// loginAttr returns the attribute the bind DN pattern puts the login in ("uid"
// for "uid=%s,ou=people,dc=example,dc=com"), or "" when the pattern does not
// have that shape.
func (a *Authenticator) loginAttr() string {
	pattern := a.cfg.BindDNPattern
	i := strings.Index(pattern, "=%s")
	if i < 0 {
		return ""
	}
	return strings.TrimSpace(pattern[strings.LastIndexAny(pattern[:i], ",+")+1 : i])
}

// canonicalLogin picks, among the values the entry stores for its login
// attribute, the one the typed login matched, compared the way the directory
// does (case and surrounding/repeated spaces ignored). The attribute may be
// multi-valued, so the match matters; without one the typed login is kept.
func canonicalLogin(typed string, stored []string) string {
	for _, v := range stored {
		if FoldLogin(v) == FoldLogin(typed) {
			return v
		}
	}
	return typed
}

// FoldLogin reduces a login to the form under which the directory considers two
// logins equal: lower case, without surrounding spaces, inner runs of spaces
// collapsed. Use it to key anything per user before the directory has said who
// the user is (login rate limiting), so variants of one login share a key.
func FoldLogin(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

// ProfileLookupEnabled reports whether the directory can be queried for
// arbitrary users. This is possible whenever LDAP is configured: a service
// account is used when set, otherwise the query is attempted anonymously (many
// directories allow anonymous reads of name/photo). Without LDAP, only a user's
// own profile can be read — at their own login.
func (a *Authenticator) ProfileLookupEnabled() bool {
	return a.cfg.Configured()
}

// LookupProfile resolves the display name and photo of an arbitrary user by
// uid. It binds with the configured service account when set, and otherwise
// queries anonymously. It is meant to populate directory data (e.g. on the
// admin machines list) for users who never logged in.
func (a *Authenticator) LookupProfile(uid string) (name string, photo []byte, err error) {
	if !a.cfg.Configured() {
		return "", nil, ErrProfileUnavailable
	}
	conn, err := a.dial()
	if err != nil {
		return "", nil, err
	}
	defer conn.Close()
	// Bind as the service account when configured; otherwise stay unauthenticated
	// (anonymous) and rely on the directory allowing anonymous reads.
	if a.cfg.SearchBindDN != "" {
		if err := conn.Bind(a.cfg.SearchBindDN, a.cfg.SearchBindPassword); err != nil {
			return "", nil, fmt.Errorf("ldap search bind: %w", err)
		}
	}
	userDN := fmt.Sprintf(a.cfg.BindDNPattern, ldap.EscapeDN(uid))
	_, name, photo, err = a.lookupProfile(conn, userDN, "")
	return name, photo, err
}

// Presence is the outcome of a directory existence check for a user.
type Presence int

const (
	// PresenceUnknown means the directory could not answer: LDAP is not
	// configured, the server is unreachable, or the bind was refused. It is
	// never evidence that the user is gone — callers must treat it as "no new
	// information" rather than as an absence.
	PresenceUnknown Presence = iota
	// PresencePresent means the user's entry was found.
	PresencePresent
	// PresenceAbsent means the directory answered and the entry is not there.
	PresenceAbsent
)

// LookupPresence reports whether uid still has an entry in the directory. It is
// the offboarding check: a user removed from the directory should not keep a
// working VPN peer.
//
// The distinction between "answered, not there" and "could not ask" is the
// whole point of the method, so the three cases are kept apart deliberately: a
// directory outage, a revoked service account or a directory that stopped
// allowing anonymous reads all yield PresenceUnknown, never PresenceAbsent.
func (a *Authenticator) LookupPresence(uid string) (Presence, error) {
	if !a.cfg.Configured() {
		return PresenceUnknown, ErrProfileUnavailable
	}
	conn, err := a.dial()
	if err != nil {
		return PresenceUnknown, err
	}
	defer conn.Close()
	if a.cfg.SearchBindDN != "" {
		if err := conn.Bind(a.cfg.SearchBindDN, a.cfg.SearchBindPassword); err != nil {
			return PresenceUnknown, fmt.Errorf("ldap search bind: %w", err)
		}
	}
	userDN := fmt.Sprintf(a.cfg.BindDNPattern, ldap.EscapeDN(uid))
	// "1.1" is the OID for "no attributes": we only care whether the entry is
	// there, so there is no reason to pull a photo across the network.
	req := ldap.NewSearchRequest(
		userDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", []string{"1.1"}, nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return PresenceAbsent, nil
		}
		return PresenceUnknown, fmt.Errorf("ldap presence search: %w", err)
	}
	if len(res.Entries) == 0 {
		return PresenceAbsent, nil
	}
	return PresencePresent, nil
}

// lookupProfile reads the user's display-name (cn by default) and photo
// (jpegPhoto by default) attributes with a base-scoped search on the user DN,
// plus the values of loginAttr when it is not empty.
// A search transport error is returned so callers can avoid caching an empty
// profile after a transient failure; a genuinely absent entry or attribute is
// not an error (empty name/photo, nil error) so it can be cached as "known
// empty" without re-querying on every page load.
func (a *Authenticator) lookupProfile(conn *ldap.Conn, userDN, loginAttr string) (logins []string, name string, photo []byte, err error) {
	nameAttr := a.cfg.NameAttr
	if nameAttr == "" {
		nameAttr = "cn"
	}
	attrs := []string{nameAttr}
	if a.cfg.PhotoAttr != "" {
		attrs = append(attrs, a.cfg.PhotoAttr)
	}
	if loginAttr != "" {
		attrs = append(attrs, loginAttr)
	}
	req := ldap.NewSearchRequest(
		userDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", attrs, nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, "", nil, err
	}
	if len(res.Entries) == 0 {
		return nil, "", nil, nil
	}
	entry := res.Entries[0]
	name = entry.GetAttributeValue(nameAttr)
	if a.cfg.PhotoAttr != "" {
		photo = entry.GetRawAttributeValue(a.cfg.PhotoAttr)
	}
	if loginAttr != "" {
		logins = entry.GetAttributeValues(loginAttr)
	}
	return logins, name, photo, nil
}

// isMember checks membership of the admin group on the given connection.
func (a *Authenticator) isMember(conn *ldap.Conn, uid, userDN string) (bool, error) {
	memberAttr := a.cfg.MemberAttr
	if memberAttr == "" {
		memberAttr = "memberUid"
	}
	memberValue := uid
	if !strings.EqualFold(memberAttr, "memberUid") {
		memberValue = userDN
	}

	req := ldap.NewSearchRequest(
		a.cfg.AdminGroupDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		fmt.Sprintf("(%s=%s)", memberAttr, ldap.EscapeFilter(memberValue)),
		[]string{"dn"}, nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		// A "no such object" simply means the group has no matching member.
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return false, nil
		}
		return false, fmt.Errorf("ldap group search: %w", err)
	}
	return len(res.Entries) > 0, nil
}
