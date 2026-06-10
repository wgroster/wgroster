package store

import (
	"database/sql"
	"errors"
)

// GetSetting returns the value for a key and whether it exists.
func (s *Store) GetSetting(name string) (string, bool, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM setting WHERE name=?`, name).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// SetSetting stores (upserts) a key/value pair.
func (s *Store) SetSetting(name, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO setting (name, value) VALUES (?, ?)
		 ON CONFLICT(name) DO UPDATE SET value=excluded.value`,
		name, value)
	return err
}
