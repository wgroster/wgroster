// Package web wires the HTTP handlers, templates and middleware together.
package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"log"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/wgroster/wgroster/internal/auth"
	"github.com/wgroster/wgroster/internal/config"
	"github.com/wgroster/wgroster/internal/geoip"
	"github.com/wgroster/wgroster/internal/ipam"
	"github.com/wgroster/wgroster/internal/ldap"
	"github.com/wgroster/wgroster/internal/store"
)

//go:embed static/*
var staticFS embed.FS

// Server holds the shared dependencies for all handlers.
type Server struct {
	cfg   *config.Config
	store *store.Store
	auth  *ldap.Authenticator
	sess  *auth.Manager
	pool  *ipam.Pool
	geo   *geoip.Lookup

	loginLimiter *limiter // per source IP
	userLimiter  *limiter // per submitted username
	assetVersion string   // content hash for cache-busting /static URLs
	version      string   // build version ("dev" for local/untagged builds)

	profileMu       sync.Mutex      // guards profileInflight
	profileInflight map[string]bool // uids being refreshed from LDAP right now

	statusMu       sync.Mutex       // guards the fleet-status cache below
	statusCache    []endpointStatus // last built fleet status (nil until built)
	statusCachedAt time.Time
}

// New builds a Server and parses the embedded templates. version is the build
// version stamp (e.g. a release tag), or "dev" for local/untagged builds.
func New(cfg *config.Config, st *store.Store, a *ldap.Authenticator, pool *ipam.Pool, geo *geoip.Lookup, version string) (*Server, error) {
	if err := loadTemplates(); err != nil {
		return nil, err
	}
	return &Server{
		cfg:             cfg,
		store:           st,
		auth:            a,
		sess:            auth.NewManager(st, cfg.SessionKey, cfg.CookieSecure, cfg.SessionTTL, cfg.SessionMaxLifetime),
		pool:            pool,
		geo:             geo,
		loginLimiter:    newLimiter(10, 5), // burst 10, refill 5 per minute, per IP
		userLimiter:     newLimiter(10, 5), // burst 10, refill 5 per minute, per username
		assetVersion:    staticVersion(),
		version:         version,
		profileInflight: map[string]bool{},
	}, nil
}

// staticVersion returns a short content hash of the embedded assets, used to
// cache-bust /static URLs so a redeploy never serves stale CSS/JS.
func staticVersion() string {
	entries, err := fs.ReadDir(staticFS, "static")
	if err != nil {
		return "dev"
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)

	h := sha256.New()
	for _, n := range names {
		b, err := staticFS.ReadFile("static/" + n)
		if err != nil {
			continue
		}
		h.Write([]byte(n))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:8]
}

// Handler returns the configured HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	// Self-hosted, embedded assets (Tailwind CSS, htmx, qrcode, app.js).
	assets := http.FileServerFS(staticFS)
	mux.Handle("GET /static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// URLs are content-versioned (?v=hash), so the body for a given URL never
		// changes — but only cache long-lived when a version is supplied.
		if r.URL.Query().Get("v") != "" {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		assets.ServeHTTP(w, r)
	}))

	// Authentication.
	mux.HandleFunc("GET /login", s.handleLoginForm)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("POST /logout", s.user(s.handleLogout))
	mux.HandleFunc("POST /account/password", s.user(s.handleChangePassword))

	// User area.
	mux.HandleFunc("GET /{$}", s.user(s.handleDashboard))
	mux.HandleFunc("POST /machines", s.user(s.handleAddMachine))
	mux.HandleFunc("POST /machines/enroll", s.user(s.handleEnroll))
	mux.HandleFunc("POST /machines/{id}", s.user(s.handleEditMachine))
	mux.HandleFunc("GET /machines/{id}/config", s.user(s.handleMachineConfig))
	mux.HandleFunc("POST /machines/{id}/delete", s.user(s.handleDeleteMachine))
	mux.HandleFunc("GET /avatar/{uid}", s.user(s.handleAvatar))

	// Admin area.
	mux.HandleFunc("GET /admin/machines", s.admin(s.handleAdminMachines))
	mux.HandleFunc("POST /admin/machines", s.admin(s.handleAdminCreateMachine))
	mux.HandleFunc("POST /admin/machines/{id}", s.admin(s.handleUpdateMachine))
	mux.HandleFunc("POST /admin/machines/{id}/delete", s.admin(s.handleAdminDeleteMachine))
	mux.HandleFunc("GET /admin/endpoints", s.admin(s.handleAdminEndpoints))
	mux.HandleFunc("POST /admin/endpoints", s.admin(s.handleCreateEndpoint))
	mux.HandleFunc("POST /admin/endpoints/{id}", s.admin(s.handleUpdateEndpoint))
	mux.HandleFunc("GET /admin/endpoints/{id}/config", s.admin(s.handleEndpointConfig))
	mux.HandleFunc("POST /admin/endpoints/{id}/regenerate-token", s.admin(s.handleRegenerateToken))
	mux.HandleFunc("POST /admin/endpoints/{id}/delete", s.admin(s.handleDeleteEndpoint))
	mux.HandleFunc("GET /admin/status", s.admin(s.handleAdminStatus))
	mux.HandleFunc("GET /admin/status/table", s.admin(s.handleAdminStatusTable))
	mux.HandleFunc("GET /admin/peer", s.admin(s.handlePeerDetail))
	mux.HandleFunc("POST /admin/peers/adopt", s.admin(s.handleAdoptPeer))
	mux.HandleFunc("POST /admin/peers/link", s.admin(s.handleLinkPeer))
	mux.HandleFunc("GET /admin/audit", s.admin(s.handleAdminAudit))

	// Machine-to-machine API (bearer token per endpoint).
	mux.HandleFunc("POST /api/endpoints/{id}/status", s.handleStatusUpload)
	mux.HandleFunc("GET /api/endpoints/{id}/expected-peers", s.handleExpectedPeers)
	mux.HandleFunc("GET /api/endpoints/{id}/config", s.handleEndpointConfigAPI)

	// Monitoring.
	mux.HandleFunc("GET /metrics", s.handleMetrics)

	return s.accessLog(s.securityHeaders(mux))
}

// serverError logs the underlying error and returns a generic 500 to the client
// so internal details (SQL, file paths) never leak.
func (s *Server) serverError(w http.ResponseWriter, err error) {
	log.Printf("error: %v", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
}

// contentSecurityPolicy locks the page to first-party resources only. All
// assets (CSS/JS) are self-hosted and there is no inline script or style, so
// no 'unsafe-inline'/'unsafe-eval' is needed. QR codes render to data: images.
// form-action is spelled out because default-src does not cover it: it keeps an
// injected form from posting credentials or a CSRF token to another origin.
const contentSecurityPolicy = "default-src 'self'; " +
	"base-uri 'self'; object-src 'none'; frame-ancestors 'none'; " +
	"form-action 'self'; " +
	"img-src 'self' data:; font-src 'self'; connect-src 'self'; " +
	"style-src 'self'; script-src 'self'"

func pathID(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("id"), 10, 64)
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		// Only advertise HSTS when we are (expected to be) served over HTTPS.
		if s.cfg.CookieSecure {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}
