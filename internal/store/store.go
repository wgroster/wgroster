// Package store provides SQLite-backed persistence for the portal.
package store

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	_ "modernc.org/sqlite"
)

// Store wraps the database connection.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS endpoint (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  name                 TEXT NOT NULL UNIQUE,
  public_key           TEXT NOT NULL,
  host_port            TEXT NOT NULL,
  allowed_ips          TEXT NOT NULL DEFAULT '',
  dns                  TEXT NOT NULL DEFAULT '',
  mtu                  INTEGER NOT NULL DEFAULT 0,
  persistent_keepalive INTEGER NOT NULL DEFAULT 0,
  tunnel_ip            TEXT NOT NULL DEFAULT '',
  upload_token         TEXT NOT NULL,
  created_at           INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS machine (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_uid   TEXT NOT NULL,
  name        TEXT NOT NULL,
  public_key  TEXT NOT NULL UNIQUE,
  address     TEXT NOT NULL DEFAULT '',
  status      TEXT NOT NULL DEFAULT 'pending',
  created_at  INTEGER NOT NULL,
  approved_at INTEGER,
  approved_by TEXT NOT NULL DEFAULT '',
  owner_name  TEXT NOT NULL DEFAULT '',
  -- When the machine entered the review queue. Pending retention counts from
  -- here rather than from created_at, so a machine sent back to pending long
  -- after it was created gets a full review window instead of being swept on
  -- the next pass.
  pending_since INTEGER NOT NULL DEFAULT 0
);

-- An endpoint public key must be unique across the fleet.
CREATE UNIQUE INDEX IF NOT EXISTS idx_endpoint_public_key ON endpoint(public_key);

-- An address may be assigned to at most one machine (empty = not yet assigned).
CREATE UNIQUE INDEX IF NOT EXISTS idx_machine_address
  ON machine(address) WHERE address <> '';

CREATE TABLE IF NOT EXISTS machine_endpoint (
  machine_id  INTEGER NOT NULL REFERENCES machine(id) ON DELETE CASCADE,
  endpoint_id INTEGER NOT NULL REFERENCES endpoint(id) ON DELETE CASCADE,
  PRIMARY KEY (machine_id, endpoint_id)
);

CREATE TABLE IF NOT EXISTS status_peer (
  endpoint_id     INTEGER NOT NULL REFERENCES endpoint(id) ON DELETE CASCADE,
  public_key      TEXT NOT NULL,
  last_handshake  INTEGER NOT NULL DEFAULT 0,
  rx              INTEGER NOT NULL DEFAULT 0,
  tx              INTEGER NOT NULL DEFAULT 0,
  remote_endpoint TEXT NOT NULL DEFAULT '',
  allowed_ips     TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (endpoint_id, public_key)
);

-- The dashboard and the admin machines list resolve a peer by public key alone
-- (across every endpoint). The primary key is (endpoint_id, public_key), whose
-- leading column is the endpoint, so without this index each lookup scans the
-- whole table — once per machine, on every 20s dashboard poll.
CREATE INDEX IF NOT EXISTS idx_status_peer_key ON status_peer(public_key);

CREATE TABLE IF NOT EXISTS status_report (
  endpoint_id INTEGER PRIMARY KEY REFERENCES endpoint(id) ON DELETE CASCADE,
  received_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS setting (
  name  TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Server-side sessions so a cookie can be revoked (logout, password change).
-- The cookie carries only the random sid; all session state lives here.
CREATE TABLE IF NOT EXISTS session (
  sid       TEXT PRIMARY KEY,
  uid       TEXT NOT NULL,
  name      TEXT NOT NULL DEFAULT '',
  admin     INTEGER NOT NULL DEFAULT 0,
  local     INTEGER NOT NULL DEFAULT 0,
  csrf      TEXT NOT NULL,
  issued_at INTEGER NOT NULL,
  expiry    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_session_uid ON session(uid);
CREATE INDEX IF NOT EXISTS idx_session_expiry ON session(expiry);

CREATE TABLE IF NOT EXISTS audit_log (
  id     INTEGER PRIMARY KEY AUTOINCREMENT,
  ts     INTEGER NOT NULL,
  actor  TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT ''
);

-- Cached directory profile (display name + photo) per user uid, populated from
-- LDAP at login and, when a service account is configured, lazily refreshed for
-- other users shown on the admin machines list.
CREATE TABLE IF NOT EXISTS user_profile (
  uid          TEXT PRIMARY KEY,
  display_name TEXT NOT NULL DEFAULT '',
  photo        BLOB,
  photo_type   TEXT NOT NULL DEFAULT '',
  fetched_at   INTEGER NOT NULL DEFAULT 0
);

-- Result of the directory offboarding check, one row per machine owner. It is
-- state, not a cache: misses counts consecutive "absent" answers so a single
-- LDAP hiccup cannot orphan a user, and flagged_at records that the grace
-- period has already been acted upon (so the action fires once, not daily).
CREATE TABLE IF NOT EXISTS owner_check (
  uid          TEXT PRIMARY KEY,
  misses       INTEGER NOT NULL DEFAULT 0,
  absent_since INTEGER NOT NULL DEFAULT 0,
  flagged_at   INTEGER NOT NULL DEFAULT 0,
  checked_at   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS status_history (
  endpoint_id INTEGER NOT NULL REFERENCES endpoint(id) ON DELETE CASCADE,
  public_key  TEXT NOT NULL,
  report_ts   INTEGER NOT NULL,
  rx          INTEGER NOT NULL DEFAULT 0,
  tx          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_status_history ON status_history(endpoint_id, report_ts);
-- Per-peer history (the drawer curves, first-seen) filters on the peer as well;
-- the index above only narrows to the endpoint, leaving every sample of that
-- endpoint's retention window to be scanned.
CREATE INDEX IF NOT EXISTS idx_status_history_peer
  ON status_history(endpoint_id, public_key, report_ts);

-- The retention trim runs inside every status upload and filters on report_ts
-- alone, so neither index above applies to it: without this one it scans the
-- largest table in the database once per report, per endpoint.
CREATE INDEX IF NOT EXISTS idx_status_history_ts ON status_history(report_ts);

-- Machines are listed and counted per owner on every dashboard load.
CREATE INDEX IF NOT EXISTS idx_machine_owner ON machine(owner_uid);

-- Same shape as the trim above: the hourly audit prune filters on ts alone.
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
`

// Open opens (and migrates) the SQLite database at path.
func Open(path string) (*Store, error) {
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite serialises writes; a single connection keeps things simple and
	// avoids "database is locked" under the portal's light concurrency.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	// Idempotent column additions for databases created by an earlier version.
	for _, stmt := range []string{
		`ALTER TABLE status_peer ADD COLUMN allowed_ips TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE machine ADD COLUMN approved_by TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE machine ADD COLUMN owner_name TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE machine ADD COLUMN pending_since INTEGER NOT NULL DEFAULT 0`,
	} {
		if _, err := db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			db.Close()
			return nil, fmt.Errorf("migrate: %w", err)
		}
	}

	// The database holds upload tokens and password hashes; keep it private.
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if _, err := os.Stat(p); err == nil {
			_ = os.Chmod(p, 0o600)
		}
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }
