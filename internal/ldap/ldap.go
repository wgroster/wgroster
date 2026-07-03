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

// Authenticate verifies the user's credentials and returns the user's display
// name (cn), photo (may be nil) and whether the user is an administrator. The
// uid is the login typed on the form.
func (a *Authenticator) Authenticate(uid, password string) (name string, photo []byte, isAdmin bool, err error) {
	if password == "" {
		return "", nil, false, ErrInvalidCredentials
	}
	conn, err := a.dial()
	if err != nil {
		return "", nil, false, err
	}
	defer conn.Close()

	userDN := fmt.Sprintf(a.cfg.BindDNPattern, ldap.EscapeDN(uid))
	if err := conn.Bind(userDN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return "", nil, false, ErrInvalidCredentials
		}
		return "", nil, false, fmt.Errorf("ldap bind: %w", err)
	}

	// Connection used for lookups: a service account when configured, otherwise
	// the user's own (already authenticated) connection.
	search := conn
	if a.cfg.SearchBindDN != "" {
		sc, err := a.dial()
		if err != nil {
			return "", nil, false, err
		}
		defer sc.Close()
		if err := sc.Bind(a.cfg.SearchBindDN, a.cfg.SearchBindPassword); err != nil {
			return "", nil, false, fmt.Errorf("ldap search bind: %w", err)
		}
		search = sc
	}

	// A failed profile read must not fail the login; treat name/photo as best-effort.
	name, photo, _ = a.lookupProfile(search, userDN)
	if a.cfg.AdminGroupDN != "" {
		isAdmin, err = a.isMember(search, uid, userDN)
		if err != nil {
			return "", nil, false, err
		}
	}
	return name, photo, isAdmin, nil
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
	return a.lookupProfile(conn, userDN)
}

// lookupProfile reads the user's display-name (cn by default) and photo
// (jpegPhoto by default) attributes with a base-scoped search on the user DN.
// A search transport error is returned so callers can avoid caching an empty
// profile after a transient failure; a genuinely absent entry or attribute is
// not an error (empty name/photo, nil error) so it can be cached as "known
// empty" without re-querying on every page load.
func (a *Authenticator) lookupProfile(conn *ldap.Conn, userDN string) (name string, photo []byte, err error) {
	nameAttr := a.cfg.NameAttr
	if nameAttr == "" {
		nameAttr = "cn"
	}
	attrs := []string{nameAttr}
	if a.cfg.PhotoAttr != "" {
		attrs = append(attrs, a.cfg.PhotoAttr)
	}
	req := ldap.NewSearchRequest(
		userDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", attrs, nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return "", nil, err
	}
	if len(res.Entries) == 0 {
		return "", nil, nil
	}
	name = res.Entries[0].GetAttributeValue(nameAttr)
	if a.cfg.PhotoAttr != "" {
		photo = res.Entries[0].GetRawAttributeValue(a.cfg.PhotoAttr)
	}
	return name, photo, nil
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
