// Package ldap authenticates users against an OpenLDAP directory and resolves
// administrator membership from a group.
package ldap

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"

	"github.com/wgroster/wgroster/internal/config"
	"github.com/go-ldap/ldap/v3"
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

// Authenticate verifies the user's credentials and returns the user's display
// name (cn) and whether the user is an administrator. The uid is the login
// typed on the form.
func (a *Authenticator) Authenticate(uid, password string) (name string, isAdmin bool, err error) {
	if password == "" {
		return "", false, ErrInvalidCredentials
	}
	conn, err := a.dial()
	if err != nil {
		return "", false, err
	}
	defer conn.Close()

	userDN := fmt.Sprintf(a.cfg.BindDNPattern, ldap.EscapeDN(uid))
	if err := conn.Bind(userDN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return "", false, ErrInvalidCredentials
		}
		return "", false, fmt.Errorf("ldap bind: %w", err)
	}

	// Connection used for lookups: a service account when configured, otherwise
	// the user's own (already authenticated) connection.
	search := conn
	if a.cfg.SearchBindDN != "" {
		sc, err := a.dial()
		if err != nil {
			return "", false, err
		}
		defer sc.Close()
		if err := sc.Bind(a.cfg.SearchBindDN, a.cfg.SearchBindPassword); err != nil {
			return "", false, fmt.Errorf("ldap search bind: %w", err)
		}
		search = sc
	}

	name = a.lookupName(search, userDN)
	if a.cfg.AdminGroupDN != "" {
		isAdmin, err = a.isMember(search, uid, userDN)
		if err != nil {
			return "", false, err
		}
	}
	return name, isAdmin, nil
}

// lookupName reads the user's display-name attribute (cn by default).
func (a *Authenticator) lookupName(conn *ldap.Conn, userDN string) string {
	attr := a.cfg.NameAttr
	if attr == "" {
		attr = "cn"
	}
	req := ldap.NewSearchRequest(
		userDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", []string{attr}, nil,
	)
	res, err := conn.Search(req)
	if err != nil || len(res.Entries) == 0 {
		return ""
	}
	return res.Entries[0].GetAttributeValue(attr)
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
