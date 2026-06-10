package web

import (
	"context"
	"crypto/subtle"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/wgroster/wgroster/internal/auth"
)

// maxFormBytes caps the size of form request bodies.
const maxFormBytes = 1 << 20

// accessLog logs one line per request (method, path, status, duration). The
// health check is skipped to avoid noise.
func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.Printf("%s %s %s %d %s", s.clientIP(r), r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Millisecond))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

type ctxKey int

const sessionCtxKey ctxKey = iota

// sessionFrom returns the session attached to the request context.
func sessionFrom(r *http.Request) *auth.Session {
	s, _ := r.Context().Value(sessionCtxKey).(*auth.Session)
	return s
}

// user wraps a handler requiring an authenticated session. For non-GET requests
// it also enforces the CSRF token.
func (s *Server) user(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := s.sess.Read(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
			if crossOrigin(r) {
				http.Error(w, "cross-origin request rejected", http.StatusForbidden)
				return
			}
			if !validCSRF(r, sess) {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		// Sliding expiry: extend the session on each authenticated request.
		s.sess.Refresh(w, sess)
		h(w, r.WithContext(context.WithValue(r.Context(), sessionCtxKey, sess)))
	}
}

// admin wraps a handler requiring an authenticated administrator session.
func (s *Server) admin(h http.HandlerFunc) http.HandlerFunc {
	return s.user(func(w http.ResponseWriter, r *http.Request) {
		if sess := sessionFrom(r); sess == nil || !sess.Admin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h(w, r)
	})
}

func validCSRF(r *http.Request, sess *auth.Session) bool {
	// Read the token from the POST body only: r.FormValue would also accept it
	// from the URL query string, where tokens can leak via logs and history.
	token := r.PostFormValue("csrf")
	return subtle.ConstantTimeCompare([]byte(token), []byte(sess.CSRF)) == 1
}

// clientIP returns the caller's IP, honouring X-Forwarded-For only when the
// portal is configured to sit behind a trusted reverse proxy. It uses the
// rightmost XFF entry — the hop appended by the trusted proxy — because a client
// can prepend arbitrary values to the header. Using the leftmost entry would let
// an attacker spoof their source IP (defeating per-IP login rate-limiting and
// poisoning logs) by sending their own X-Forwarded-For.
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustedProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.LastIndexByte(xff, ','); i >= 0 {
				return strings.TrimSpace(xff[i+1:])
			}
			return strings.TrimSpace(xff)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// crossOrigin reports whether the request is known to come from a different
// origin than the one it targets, using the Origin header (falling back to
// Referer). It returns false when neither header is present (e.g. a non-browser
// API client), so it never blocks legitimate same-origin or header-less callers
// — browsers reliably send Origin on cross-site POSTs, which is the CSRF vector.
func crossOrigin(r *http.Request) bool {
	src := r.Header.Get("Origin")
	if src == "" {
		src = r.Header.Get("Referer")
	}
	if src == "" {
		return false
	}
	u, err := url.Parse(src)
	if err != nil || u.Host == "" {
		return true // malformed header: treat as cross-origin
	}
	return !strings.EqualFold(u.Host, r.Host)
}

// limiter is a simple per-key token bucket (refilled per minute). Idle buckets
// are evicted periodically so the map cannot grow without bound.
type limiter struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	burst     float64
	perMin    float64
	lastSweep time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(burst, perMin float64) *limiter {
	return &limiter{buckets: map[string]*bucket{}, burst: burst, perMin: perMin}
}

// allow reports whether an action is permitted for key, consuming a token.
func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.lastSweep) > 10*time.Minute {
		for k, b := range l.buckets {
			if now.Sub(b.last) > time.Hour {
				delete(l.buckets, k)
			}
		}
		l.lastSweep = now
	}
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Minutes()
	b.tokens = min(l.burst, b.tokens+elapsed*l.perMin)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
