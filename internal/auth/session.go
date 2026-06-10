// Package auth provides server-side sessions referenced by an HMAC-signed
// cookie, plus CSRF tokens. The cookie carries only an opaque random session id;
// all session state lives in a SessionStore, so a session can be revoked
// server-side (logout, password change) — clearing the client cookie is not
// enough on its own.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"time"
)

const (
	// baseCookieName is used over plain HTTP. When the Secure flag is set we use
	// hostCookieName instead: the __Host- prefix tells the browser to enforce
	// Secure + Path=/ + no Domain, preventing cookie fixation from a subdomain or
	// an active network attacker.
	baseCookieName    = "wg_session"
	hostCookieName    = "__Host-wg_session"
	defaultSessionTTL = 12 * time.Hour
	sidBytes          = 32 // 256 bits of entropy for the session id
)

// ErrNoSession is returned by a SessionStore when the sid is unknown.
var ErrNoSession = errors.New("no such session")

// Session is a server-side session record. It is returned to handlers; the
// cookie only ever holds SID.
type Session struct {
	SID      string
	UID      string
	Name     string // display name (LDAP cn); may be empty
	Admin    bool
	Local    bool // authenticated via the local admin account
	CSRF     string
	IssuedAt time.Time
	Expiry   time.Time
}

// Display returns the name when set, otherwise the uid.
func (s *Session) Display() string {
	if s.Name != "" {
		return s.Name
	}
	return s.UID
}

// SessionStore persists server-side sessions.
type SessionStore interface {
	CreateSession(s *Session) error
	Session(sid string) (*Session, error) // (nil, ErrNoSession) when absent
	TouchSession(sid string, expiry time.Time) error
	DeleteSession(sid string) error
	DeleteSessionsByUID(uid string) error
	DeleteExpiredSessions(now time.Time) (int64, error)
}

// Manager issues, verifies and revokes sessions.
type Manager struct {
	store   SessionStore
	key     []byte
	secure  bool
	cookie  string        // cookie name (host-prefixed when secure)
	ttl     time.Duration // sliding lifetime, extended on activity
	maxLife time.Duration // absolute lifetime cap, measured from IssuedAt
}

// NewManager returns a Manager backed by store. key signs the sid cookie. ttl is
// the sliding session lifetime; maxLife is the absolute lifetime cap (a session
// is rejected once older than this, no matter how often it is refreshed). A
// non-positive ttl falls back to the default; a maxLife below ttl is raised to
// ttl so the cap never undercuts a single sliding window.
func NewManager(store SessionStore, key string, secure bool, ttl, maxLife time.Duration) *Manager {
	if ttl <= 0 {
		ttl = defaultSessionTTL
	}
	if maxLife < ttl {
		maxLife = ttl
	}
	cookie := baseCookieName
	if secure {
		cookie = hostCookieName
	}
	return &Manager{store: store, key: []byte(key), secure: secure, cookie: cookie, ttl: ttl, maxLife: maxLife}
}

func (m *Manager) sign(data []byte) string {
	mac := hmac.New(sha256.New, m.key)
	mac.Write(data)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// writeCookie sets the session cookie to the (signed) sid with the given expiry.
func (m *Manager) writeCookie(w http.ResponseWriter, sid string, expiry time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookie,
		Value:    sid + "." + m.sign([]byte(sid)),
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiry,
	})
}

// Issue creates a server-side session for the user and writes the cookie.
func (m *Manager) Issue(w http.ResponseWriter, uid, name string, admin, local bool) (*Session, error) {
	sid, err := RandomToken(sidBytes)
	if err != nil {
		return nil, err
	}
	csrf, err := RandomToken(24)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	s := &Session{
		SID: sid, UID: uid, Name: name, Admin: admin, Local: local,
		CSRF: csrf, IssuedAt: now, Expiry: now.Add(m.ttl),
	}
	if err := m.store.CreateSession(s); err != nil {
		return nil, err
	}
	m.writeCookie(w, s.SID, s.Expiry)
	return s, nil
}

// Refresh extends a valid session's lifetime (sliding expiry), updating both the
// stored expiry and the cookie. The new expiry is capped at the absolute
// deadline (IssuedAt + maxLife) so refreshing can never push a session past it.
func (m *Manager) Refresh(w http.ResponseWriter, s *Session) {
	newExpiry := time.Now().Add(m.ttl)
	if deadline := s.IssuedAt.Add(m.maxLife); newExpiry.After(deadline) {
		newExpiry = deadline
	}
	s.Expiry = newExpiry
	if err := m.store.TouchSession(s.SID, s.Expiry); err != nil {
		return
	}
	m.writeCookie(w, s.SID, s.Expiry)
}

// Destroy revokes a single session (logout on this device) and clears the
// cookie.
func (m *Manager) Destroy(w http.ResponseWriter, sid string) {
	if sid != "" {
		_ = m.store.DeleteSession(sid)
	}
	m.clearCookie(w)
}

// RevokeUser revokes every session belonging to uid (e.g. on password change).
func (m *Manager) RevokeUser(uid string) error {
	return m.store.DeleteSessionsByUID(uid)
}

// clearCookie removes the session cookie from the client.
func (m *Manager) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// errInvalid is returned for any missing, malformed or expired session cookie.
var errInvalid = errors.New("invalid session")

// Read parses the cookie, verifies its signature, and loads the live
// server-side session. A revoked session no longer exists in the store, so its
// cookie is rejected here.
func (m *Manager) Read(r *http.Request) (*Session, error) {
	c, err := r.Cookie(m.cookie)
	if err != nil {
		return nil, errInvalid
	}
	sid, sig, ok := cut(c.Value, '.')
	if !ok {
		return nil, errInvalid
	}
	expected := m.sign([]byte(sid))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) != 1 {
		return nil, errInvalid
	}
	s, err := m.store.Session(sid)
	if err != nil {
		return nil, errInvalid
	}
	now := time.Now()
	// Reject on either the sliding expiry or the absolute lifetime cap.
	if now.After(s.Expiry) || now.After(s.IssuedAt.Add(m.maxLife)) {
		_ = m.store.DeleteSession(sid)
		return nil, errInvalid
	}
	return s, nil
}

// SweepExpired purges expired sessions and returns how many were removed.
func (m *Manager) SweepExpired() (int64, error) {
	return m.store.DeleteExpiredSessions(time.Now())
}

func cut(s string, sep byte) (before, after string, found bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

// RandomToken returns a URL-safe random token of n bytes of entropy.
func RandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
