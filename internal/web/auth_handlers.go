package web

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"github.com/wgroster/wgroster/internal/ldap"
	"golang.org/x/crypto/bcrypt"
)

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	// Already logged in? Go to the dashboard.
	if _, err := s.sess.Read(r); err == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, "login", "Sign in", "", nil)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Login has no session yet, so the form-token CSRF check does not apply here.
	// Reject cross-origin POSTs to prevent login CSRF (an attacker silently
	// logging a victim into the attacker's account).
	if crossOrigin(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	if !s.loginLimiter.allow(s.clientIP(r)) {
		http.Redirect(w, r, "/login?err=Too+many+attempts,+try+again+later", http.StatusSeeOther)
		return
	}
	uid := r.FormValue("uid")
	password := r.FormValue("password")
	if uid == "" || password == "" {
		http.Redirect(w, r, "/login?err=Missing+credentials", http.StatusSeeOther)
		return
	}
	// Also rate-limit per username (lower-cased) so distributing attempts across
	// many source IPs cannot brute-force one account unthrottled.
	if !s.userLimiter.allow(strings.ToLower(uid)) {
		http.Redirect(w, r, "/login?err=Too+many+attempts,+try+again+later", http.StatusSeeOther)
		return
	}

	// The local admin account is checked before LDAP.
	if matched, ok := s.localAdminLogin(uid, password); matched {
		if !ok {
			http.Redirect(w, r, "/login?err=Invalid+credentials", http.StatusSeeOther)
			return
		}
		if _, err := s.sess.Issue(w, uid, "", true, true); err != nil {
			http.Error(w, "session error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if !s.cfg.LDAP.Configured() {
		http.Redirect(w, r, "/login?err=Invalid+credentials", http.StatusSeeOther)
		return
	}

	name, photo, admin, err := s.auth.Authenticate(uid, password)
	if err != nil {
		if errors.Is(err, ldap.ErrInvalidCredentials) {
			http.Redirect(w, r, "/login?err=Invalid+credentials", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/login?err=Authentication+error", http.StatusSeeOther)
		return
	}

	// Cache the directory profile (name + photo) and keep the cached owner name
	// on this user's machines fresh (and backfill older rows).
	s.cacheProfile(uid, name, photo)

	if _, err := s.sess.Issue(w, uid, name, admin, false); err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// localPasswordKey is the setting holding the runtime-overridden bcrypt hash for
// the local admin password (takes precedence over the config value).
const localPasswordKey = "local_admin_password_hash"

// localAdminLogin verifies credentials against the local admin account. A hash
// stored in the database (set via the change-password form) takes precedence
// over the configured hash/password. matched is true when uid is the local
// admin (so the caller must not fall through to LDAP); ok is true when the
// password is also correct.
func (s *Server) localAdminLogin(uid, password string) (matched, ok bool) {
	la := s.cfg.LocalAdmin
	if !la.Enabled() || uid != la.Username {
		return false, false
	}
	if hash, found, err := s.store.GetSetting(localPasswordKey); err == nil && found && hash != "" {
		return true, bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	}
	if la.PasswordHash != "" {
		return true, bcrypt.CompareHashAndPassword([]byte(la.PasswordHash), []byte(password)) == nil
	}
	// Clear-text fallback (development only).
	return true, subtle.ConstantTimeCompare([]byte(password), []byte(la.Password)) == 1
}

// handleChangePassword updates the local admin password (stored as a bcrypt
// hash in the database). Only the local admin session may use it.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if sess == nil || !sess.Local {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	current := r.FormValue("current_password")
	next := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	if _, ok := s.localAdminLogin(sess.UID, current); !ok {
		redirectMsg(w, r, "/", "err", "Current password is incorrect")
		return
	}
	if len(next) < 8 {
		redirectMsg(w, r, "/", "err", "New password must be at least 8 characters")
		return
	}
	if next != confirm {
		redirectMsg(w, r, "/", "err", "New passwords do not match")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(next), bcrypt.DefaultCost)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if err := s.store.SetSetting(localPasswordKey, string(hash)); err != nil {
		s.serverError(w, err)
		return
	}
	// Revoke every existing session for this account (any other device using the
	// old password is logged out), then issue a fresh session so the admin who
	// just changed the password stays signed in here.
	if err := s.sess.RevokeUser(sess.UID); err != nil {
		s.serverError(w, err)
		return
	}
	if _, err := s.sess.Issue(w, sess.UID, sess.Name, sess.Admin, sess.Local); err != nil {
		s.serverError(w, err)
		return
	}
	s.audit(r, "account.password_change", sess.UID)
	redirectMsg(w, r, "/", "ok", "Password changed")
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sid := ""
	if sess := sessionFrom(r); sess != nil {
		sid = sess.SID
	}
	// Revoke the server-side session so a copy of the cookie is useless after
	// logout, then clear it from this browser.
	s.sess.Destroy(w, sid)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
