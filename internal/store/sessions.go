package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/wgroster/wgroster/internal/auth"
)

// CreateSession persists a new server-side session.
func (s *Store) CreateSession(sess *auth.Session) error {
	_, err := s.db.Exec(
		`INSERT INTO session (sid, uid, name, admin, local, csrf, issued_at, expiry)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.SID, sess.UID, sess.Name, boolToInt(sess.Admin), boolToInt(sess.Local),
		sess.CSRF, sess.IssuedAt.Unix(), sess.Expiry.Unix())
	return err
}

// Session returns the session for sid, or auth.ErrNoSession when it does not
// exist (revoked, expired-and-swept, or never issued).
func (s *Store) Session(sid string) (*auth.Session, error) {
	var (
		sess             auth.Session
		admin, local     int
		issuedAt, expiry int64
	)
	err := s.db.QueryRow(
		`SELECT sid, uid, name, admin, local, csrf, issued_at, expiry
		   FROM session WHERE sid = ?`, sid).
		Scan(&sess.SID, &sess.UID, &sess.Name, &admin, &local, &sess.CSRF, &issuedAt, &expiry)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, auth.ErrNoSession
	}
	if err != nil {
		return nil, err
	}
	sess.Admin = admin != 0
	sess.Local = local != 0
	sess.IssuedAt = time.Unix(issuedAt, 0)
	sess.Expiry = time.Unix(expiry, 0)
	return &sess, nil
}

// TouchSession extends a session's expiry (sliding refresh).
func (s *Store) TouchSession(sid string, expiry time.Time) error {
	_, err := s.db.Exec(`UPDATE session SET expiry = ? WHERE sid = ?`, expiry.Unix(), sid)
	return err
}

// DeleteSession removes a single session (logout on this device).
func (s *Store) DeleteSession(sid string) error {
	_, err := s.db.Exec(`DELETE FROM session WHERE sid = ?`, sid)
	return err
}

// DeleteSessionsByUID removes every session for a user (e.g. on password
// change), revoking all of that user's logins across devices.
func (s *Store) DeleteSessionsByUID(uid string) error {
	_, err := s.db.Exec(`DELETE FROM session WHERE uid = ?`, uid)
	return err
}

// DeleteExpiredSessions purges sessions whose expiry has passed and returns how
// many rows were removed.
func (s *Store) DeleteExpiredSessions(now time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM session WHERE expiry < ?`, now.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
