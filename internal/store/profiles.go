package store

import (
	"database/sql"
	"time"
)

// UserProfile is a user's cached directory profile.
type UserProfile struct {
	UID         string
	DisplayName string
	Photo       []byte
	PhotoType   string
	FetchedAt   time.Time
}

// UpsertUserProfile stores (or refreshes) a user's directory profile. A nil
// photo clears any previously cached one; photoType is the image MIME type.
func (s *Store) UpsertUserProfile(uid, displayName string, photo []byte, photoType string) error {
	_, err := s.db.Exec(`
		INSERT INTO user_profile (uid, display_name, photo, photo_type, fetched_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(uid) DO UPDATE SET
		  display_name = excluded.display_name,
		  photo        = excluded.photo,
		  photo_type   = excluded.photo_type,
		  fetched_at   = excluded.fetched_at`,
		uid, displayName, photo, photoType, time.Now().Unix())
	return err
}

// UserProfileMeta returns a user's display name, whether a photo is cached and
// when the profile was last fetched — without loading the (potentially large)
// photo blob. found is false when no profile is cached yet.
func (s *Store) UserProfileMeta(uid string) (displayName string, hasPhoto bool, fetchedAt time.Time, found bool, err error) {
	var fetched int64
	var photoLen int
	err = s.db.QueryRow(`SELECT display_name, COALESCE(LENGTH(photo), 0), fetched_at FROM user_profile WHERE uid=?`, uid).
		Scan(&displayName, &photoLen, &fetched)
	if err == sql.ErrNoRows {
		return "", false, time.Time{}, false, nil
	}
	if err != nil {
		return "", false, time.Time{}, false, err
	}
	return displayName, photoLen > 0, time.Unix(fetched, 0), true, nil
}

// ProfileMeta is the light part of a cached directory profile: what a listing
// page needs to render a name, decide between an avatar and an initial badge,
// and judge whether the cache is stale.
type ProfileMeta struct {
	DisplayName string
	HasPhoto    bool
	FetchedAt   time.Time
}

// AllUserProfileMetas returns every cached profile keyed by uid, without the
// photo blobs. Listing pages use it to avoid one UserProfileMeta query per user.
func (s *Store) AllUserProfileMetas() (map[string]ProfileMeta, error) {
	rows, err := s.db.Query(
		`SELECT uid, display_name, COALESCE(LENGTH(photo), 0), fetched_at FROM user_profile`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ProfileMeta{}
	for rows.Next() {
		var uid string
		var name string
		var photoLen int
		var fetched int64
		if err := rows.Scan(&uid, &name, &photoLen, &fetched); err != nil {
			return nil, err
		}
		out[uid] = ProfileMeta{DisplayName: name, HasPhoto: photoLen > 0, FetchedAt: time.Unix(fetched, 0)}
	}
	return out, rows.Err()
}

// UserPhoto returns a user's cached photo and its MIME type. found is false when
// no profile or no photo is cached.
func (s *Store) UserPhoto(uid string) (photo []byte, photoType string, found bool, err error) {
	err = s.db.QueryRow(`SELECT photo, photo_type FROM user_profile WHERE uid=?`, uid).
		Scan(&photo, &photoType)
	if err == sql.ErrNoRows {
		return nil, "", false, nil
	}
	if err != nil {
		return nil, "", false, err
	}
	if len(photo) == 0 {
		return nil, "", false, nil
	}
	return photo, photoType, true, nil
}
