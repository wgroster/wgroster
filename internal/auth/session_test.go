package auth

import (
	"net/http/httptest"
	"testing"
	"time"
)

// memStore is an in-memory SessionStore for tests.
type memStore struct{ m map[string]*Session }

func newMemStore() *memStore { return &memStore{m: map[string]*Session{}} }

func (s *memStore) CreateSession(sess *Session) error {
	cp := *sess
	s.m[sess.SID] = &cp
	return nil
}

func (s *memStore) Session(sid string) (*Session, error) {
	sess, ok := s.m[sid]
	if !ok {
		return nil, ErrNoSession
	}
	cp := *sess
	return &cp, nil
}

func (s *memStore) TouchSession(sid string, expiry time.Time) error {
	if sess, ok := s.m[sid]; ok {
		sess.Expiry = expiry
	}
	return nil
}

func (s *memStore) DeleteSession(sid string) error { delete(s.m, sid); return nil }

func (s *memStore) DeleteSessionsByUID(uid string) error {
	for sid, sess := range s.m {
		if sess.UID == uid {
			delete(s.m, sid)
		}
	}
	return nil
}

func (s *memStore) DeleteExpiredSessions(now time.Time) (int64, error) {
	var n int64
	for sid, sess := range s.m {
		if now.After(sess.Expiry) {
			delete(s.m, sid)
			n++
		}
	}
	return n, nil
}

func TestSessionTTLAndSlidingRefresh(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef"

	// ttl <= 0 falls back to the 12h default.
	m := NewManager(newMemStore(), key, false, 0, 7*24*time.Hour)
	rec := httptest.NewRecorder()
	s, err := m.Issue(rec, "bob", "Bob", true, false)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(s.Expiry); d < 11*time.Hour || d > 13*time.Hour {
		t.Errorf("default ttl ~12h expected, got %v", d)
	}

	// Refresh extends the expiry and keeps identity + CSRF.
	first := s.Expiry
	time.Sleep(10 * time.Millisecond)
	rec2 := httptest.NewRecorder()
	m.Refresh(rec2, s)
	if !s.Expiry.After(first) {
		t.Errorf("sliding refresh did not extend expiry: %v -> %v", first, s.Expiry)
	}
	// The refreshed cookie is valid and preserves the session.
	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range rec2.Result().Cookies() {
		req.AddCookie(c)
	}
	got, err := m.Read(req)
	if err != nil || got.UID != "bob" || got.CSRF != s.CSRF || !got.Admin {
		t.Fatalf("read after refresh: %+v err=%v", got, err)
	}

	// Explicit short ttl is honoured.
	m2 := NewManager(newMemStore(), key, false, 30*time.Minute, 24*time.Hour)
	rec3 := httptest.NewRecorder()
	s2, _ := m2.Issue(rec3, "x", "", false, false)
	if d := time.Until(s2.Expiry); d < 29*time.Minute || d > 31*time.Minute {
		t.Errorf("30m ttl expected, got %v", d)
	}
}

func TestSessionRevocation(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef"
	m := NewManager(newMemStore(), key, false, time.Hour, 7*24*time.Hour)

	rec := httptest.NewRecorder()
	s, err := m.Issue(rec, "bob", "Bob", false, false)
	if err != nil {
		t.Fatal(err)
	}
	read := func() (*Session, error) {
		req := httptest.NewRequest("GET", "/", nil)
		for _, c := range rec.Result().Cookies() {
			req.AddCookie(c)
		}
		return m.Read(req)
	}

	// Valid before revocation.
	if _, err := read(); err != nil {
		t.Fatalf("expected valid session, got %v", err)
	}

	// Destroy revokes this session: the cookie no longer resolves.
	m.Destroy(httptest.NewRecorder(), s.SID)
	if _, err := read(); err == nil {
		t.Fatal("expected session to be revoked after Destroy")
	}

	// RevokeUser kills all of a user's sessions.
	rec = httptest.NewRecorder()
	if _, err := m.Issue(rec, "carol", "Carol", false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := read(); err != nil {
		t.Fatalf("expected valid session for carol, got %v", err)
	}
	if err := m.RevokeUser("carol"); err != nil {
		t.Fatal(err)
	}
	if _, err := read(); err == nil {
		t.Fatal("expected carol's session to be revoked")
	}
}

func TestSessionAbsoluteLifetimeCap(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef"
	ms := newMemStore()
	// Sliding ttl 1h, absolute cap 2h.
	m := NewManager(ms, key, false, time.Hour, 2*time.Hour)

	rec := httptest.NewRecorder()
	s, err := m.Issue(rec, "bob", "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	read := func() (*Session, error) {
		req := httptest.NewRequest("GET", "/", nil)
		for _, c := range rec.Result().Cookies() {
			req.AddCookie(c)
		}
		return m.Read(req)
	}

	// Refresh caps the new expiry at the absolute deadline. With the session
	// issued 90 min ago, the deadline is now+30m, so a 1h sliding refresh must
	// not push expiry beyond ~30 min.
	ms.m[s.SID].IssuedAt = time.Now().Add(-90 * time.Minute)
	s.IssuedAt = ms.m[s.SID].IssuedAt
	rec2 := httptest.NewRecorder()
	m.Refresh(rec2, s)
	if d := time.Until(s.Expiry); d > 31*time.Minute {
		t.Errorf("refresh exceeded absolute cap: expiry in %v", d)
	}

	// Past the absolute cap, the session is rejected even with a fresh sliding
	// expiry (it would otherwise still look valid).
	ms.m[s.SID].IssuedAt = time.Now().Add(-3 * time.Hour)
	ms.m[s.SID].Expiry = time.Now().Add(time.Hour)
	if _, err := read(); err == nil {
		t.Fatal("expected session past absolute lifetime cap to be rejected")
	}
}
