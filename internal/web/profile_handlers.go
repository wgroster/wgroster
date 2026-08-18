package web

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/wgroster/wgroster/internal/store"
)

// profileTTL is how long a cached directory profile is considered fresh before
// it is lazily refreshed from LDAP (only when a service account is configured).
const profileTTL = 24 * time.Hour

// imageType sniffs the MIME type of a photo blob, defaulting to image/jpeg
// (the usual encoding of LDAP jpegPhoto). Non-image content is rejected.
func imageType(photo []byte) string {
	if len(photo) == 0 {
		return ""
	}
	ct := http.DetectContentType(photo)
	if strings.HasPrefix(ct, "image/") {
		return ct
	}
	return "image/jpeg"
}

// cacheProfile stores a user's directory name and photo, and keeps the cached
// owner name on their machines in sync. Best-effort: failures are logged.
func (s *Server) cacheProfile(uid, name string, photo []byte) {
	if err := s.store.UpsertUserProfile(uid, name, photo, imageType(photo)); err != nil {
		log.Printf("cache profile for %q: %v", uid, err)
	}
	if name != "" {
		if err := s.store.UpdateOwnerName(uid, name); err != nil {
			log.Printf("update owner name for %q: %v", uid, err)
		}
	}
}

// staleUIDs returns the uids whose cached profile is missing or older than
// profileTTL. cached is the profile map the calling page already loaded, so this
// decision costs no query.
func staleUIDs(uids []string, cached map[string]store.ProfileMeta, now time.Time) []string {
	var stale []string
	for _, uid := range uids {
		if uid == "" {
			continue
		}
		p, found := cached[uid]
		if found && now.Sub(p.FetchedAt) < profileTTL {
			continue
		}
		stale = append(stale, uid)
	}
	return stale
}

// refreshProfilesAsync refreshes, in the background, the directory profiles of
// the given uids whose cache is missing or older than profileTTL. cached is the
// profile map the calling page already holds, so deciding what is stale costs no
// further query — this runs on every status poll. It is a no-op unless the
// directory can be queried for arbitrary users (LDAP configured, with a service
// account or anonymous reads). A per-uid in-flight guard prevents concurrent
// page loads from piling up duplicate LDAP queries for the same user.
func (s *Server) refreshProfilesAsync(uids []string, cached map[string]store.ProfileMeta) {
	if !s.auth.ProfileLookupEnabled() {
		return
	}
	var stale []string
	s.profileMu.Lock()
	for _, uid := range staleUIDs(uids, cached, time.Now()) {
		if s.profileInflight[uid] {
			continue
		}
		s.profileInflight[uid] = true
		stale = append(stale, uid)
	}
	s.profileMu.Unlock()

	if len(stale) == 0 {
		return
	}
	go func() {
		for _, uid := range stale {
			name, photo, err := s.auth.LookupProfile(uid)
			if err != nil {
				log.Printf("ldap profile lookup for %q: %v", uid, err)
			} else {
				s.cacheProfile(uid, name, photo)
			}
			s.profileMu.Lock()
			delete(s.profileInflight, uid)
			s.profileMu.Unlock()
		}
	}()
}

// handleAvatar serves a user's cached directory photo. A user may fetch their
// own; an administrator may fetch anyone's. Returns 404 when no photo is cached
// so the template falls back to the initial badge.
func (s *Server) handleAvatar(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	uid := r.PathValue("uid")
	if uid == "" || (uid != sess.UID && !sess.Admin) {
		http.NotFound(w, r)
		return
	}
	photo, photoType, ok, err := s.store.UserPhoto(uid)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	if photoType == "" {
		photoType = "image/jpeg"
	}
	// Content-derived ETag so an unchanged photo returns 304 instead of the full
	// body on the next poll/reload.
	sum := sha256.Sum256(photo)
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	w.Header().Set("ETag", etag)
	// Private: a directory photo is per-user; do not let shared caches store it.
	w.Header().Set("Cache-Control", "private, max-age=300")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", photoType)
	w.Write(photo)
}
