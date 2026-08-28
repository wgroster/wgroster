package store

import (
	"database/sql"
	"errors"
	"time"
)

// OwnerCheck is the recorded state of the directory offboarding check for one
// machine owner.
type OwnerCheck struct {
	UID string
	// Misses is the number of consecutive times the directory answered that
	// this user does not exist. A round where the directory could not be asked
	// leaves it untouched.
	Misses int
	// AbsentSince is the first absent answer of the current run (zero when the
	// user is present).
	AbsentSince time.Time
	// FlaggedAt is when the grace period expired and the orphan action ran.
	// Zero while the user is still within the grace period.
	FlaggedAt time.Time
	// CheckedAt is the last time the directory gave a usable answer.
	CheckedAt time.Time
}

// Orphaned reports whether the grace period has expired for this owner.
func (c OwnerCheck) Orphaned() bool { return !c.FlaggedAt.IsZero() }

// MachineOwnerUIDs returns the distinct owners that currently have at least one
// machine. It is the population the offboarding check walks.
func (s *Store) MachineOwnerUIDs() ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT owner_uid FROM machine WHERE owner_uid <> '' ORDER BY owner_uid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var uid string
		if err := rows.Scan(&uid); err != nil {
			return nil, err
		}
		out = append(out, uid)
	}
	return out, rows.Err()
}

// OwnerChecks returns every recorded check keyed by uid.
func (s *Store) OwnerChecks() (map[string]OwnerCheck, error) {
	rows, err := s.db.Query(`SELECT uid, misses, absent_since, flagged_at, checked_at FROM owner_check`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]OwnerCheck{}
	for rows.Next() {
		var c OwnerCheck
		var absent, flagged, checked int64
		if err := rows.Scan(&c.UID, &c.Misses, &absent, &flagged, &checked); err != nil {
			return nil, err
		}
		c.AbsentSince = unixOrZero(absent)
		c.FlaggedAt = unixOrZero(flagged)
		c.CheckedAt = unixOrZero(checked)
		out[c.UID] = c
	}
	return out, rows.Err()
}

// unixOrZero converts a stored timestamp, mapping 0 to the zero time so callers
// can use IsZero rather than comparing against the epoch.
func unixOrZero(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}

// MarkOwnerPresent records that the directory still knows this user, clearing
// any accumulated absence (including a previous orphan flag, so a re-created
// account recovers on its own).
func (s *Store) MarkOwnerPresent(uid string, now time.Time) error {
	_, err := s.db.Exec(`
		INSERT INTO owner_check (uid, misses, absent_since, flagged_at, checked_at)
		VALUES (?, 0, 0, 0, ?)
		ON CONFLICT(uid) DO UPDATE SET
		  misses = 0, absent_since = 0, flagged_at = 0, checked_at = excluded.checked_at`,
		uid, now.Unix())
	return err
}

// MarkOwnerAbsent records one consecutive absence, returning the updated check.
// absent_since is kept at the first absence of the run so the admin UI can show
// how long the account has been gone.
func (s *Store) MarkOwnerAbsent(uid string, now time.Time) (OwnerCheck, error) {
	_, err := s.db.Exec(`
		INSERT INTO owner_check (uid, misses, absent_since, flagged_at, checked_at)
		VALUES (?, 1, ?, 0, ?)
		ON CONFLICT(uid) DO UPDATE SET
		  misses       = owner_check.misses + 1,
		  absent_since = CASE WHEN owner_check.absent_since = 0
		                      THEN excluded.absent_since ELSE owner_check.absent_since END,
		  checked_at   = excluded.checked_at`,
		uid, now.Unix(), now.Unix())
	if err != nil {
		return OwnerCheck{}, err
	}
	return s.OwnerCheck(uid)
}

// OwnerCheck returns one owner's recorded check (a zero value when none).
func (s *Store) OwnerCheck(uid string) (OwnerCheck, error) {
	c := OwnerCheck{UID: uid}
	var absent, flagged, checked int64
	err := s.db.QueryRow(
		`SELECT misses, absent_since, flagged_at, checked_at FROM owner_check WHERE uid=?`, uid).
		Scan(&c.Misses, &absent, &flagged, &checked)
	if errors.Is(err, sql.ErrNoRows) {
		return OwnerCheck{UID: uid}, nil
	}
	if err != nil {
		return OwnerCheck{UID: uid}, err
	}
	c.AbsentSince = unixOrZero(absent)
	c.FlaggedAt = unixOrZero(flagged)
	c.CheckedAt = unixOrZero(checked)
	return c, nil
}

// FlagOwnerOrphaned records that the orphan action has run for this owner, so
// it does not fire again on every later sweep.
func (s *Store) FlagOwnerOrphaned(uid string, now time.Time) error {
	_, err := s.db.Exec(`UPDATE owner_check SET flagged_at=? WHERE uid=?`, now.Unix(), uid)
	return err
}

// PruneOwnerChecks drops rows for users who no longer own any machine (their
// last machine was deleted), and returns how many were removed.
func (s *Store) PruneOwnerChecks() (int64, error) {
	res, err := s.db.Exec(
		`DELETE FROM owner_check WHERE uid NOT IN (SELECT owner_uid FROM machine)`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
