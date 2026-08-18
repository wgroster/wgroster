package store

import "time"

// AuditEntry is one recorded administrative action.
type AuditEntry struct {
	ID     int64
	TS     time.Time
	Actor  string
	Action string
	Target string
}

// AddAudit records an administrative action.
func (s *Store) AddAudit(actor, action, target string) error {
	_, err := s.db.Exec(
		`INSERT INTO audit_log (ts, actor, action, target) VALUES (?, ?, ?, ?)`,
		time.Now().Unix(), actor, action, target)
	return err
}

// DeleteAuditBefore removes audit entries older than cutoff and returns how many
// were deleted. The audit log is append-only and otherwise grows without bound.
func (s *Store) DeleteAuditBefore(cutoff time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM audit_log WHERE ts < ?`, cutoff.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ListAudit returns the most recent audit entries (newest first).
func (s *Store) ListAudit(limit int) ([]AuditEntry, error) {
	rows, err := s.db.Query(
		`SELECT id, ts, actor, action, target FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Action, &e.Target); err != nil {
			return nil, err
		}
		e.TS = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}
