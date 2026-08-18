package store

import (
	"database/sql"
	"errors"
	"time"
)

// ReplaceStatus atomically replaces the stored peers for an endpoint and records
// the report timestamp.
func (s *Store) ReplaceStatus(endpointID int64, peers []StatusPeer, receivedAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Preserve the last known handshake and remote endpoint across WireGuard
	// restarts: a fresh `wg show` reports handshake 0 and an empty endpoint until
	// the peer re-handshakes, which would otherwise wipe good data. Keep the
	// previous values until a newer report supersedes them. A handshake is a
	// wall-clock timestamp that only moves forward, so max() is safe; a stale
	// preserved handshake still ages past the online threshold on its own.
	type prevPeer struct {
		handshake int64
		remote    string
	}
	prev := map[string]prevPeer{}
	rows, err := tx.Query(`SELECT public_key, last_handshake, remote_endpoint FROM status_peer WHERE endpoint_id=?`, endpointID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var k, remote string
		var hs int64
		if err := rows.Scan(&k, &hs, &remote); err != nil {
			rows.Close()
			return err
		}
		prev[k] = prevPeer{handshake: hs, remote: remote}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	if _, err := tx.Exec(`DELETE FROM status_peer WHERE endpoint_id=?`, endpointID); err != nil {
		return err
	}
	for _, p := range peers {
		handshake := p.LastHandshake.Unix()
		remote := p.RemoteEndpoint
		if old, ok := prev[p.PublicKey]; ok {
			if old.handshake > handshake {
				handshake = old.handshake // keep last known across a wg restart
			}
			if remote == "" {
				remote = old.remote // hub reports no endpoint until re-handshake
			}
		}
		if _, err := tx.Exec(`
			INSERT INTO status_peer (endpoint_id, public_key, last_handshake, rx, tx, remote_endpoint, allowed_ips)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			endpointID, p.PublicKey, handshake, p.RX, p.TX, remote, p.AllowedIPs); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`
		INSERT INTO status_report (endpoint_id, received_at) VALUES (?, ?)
		ON CONFLICT(endpoint_id) DO UPDATE SET received_at=excluded.received_at`,
		endpointID, receivedAt.Unix()); err != nil {
		return err
	}

	// Append a time-series sample per peer for history/throughput.
	for _, p := range peers {
		if _, err := tx.Exec(
			`INSERT INTO status_history (endpoint_id, public_key, report_ts, rx, tx) VALUES (?, ?, ?, ?, ?)`,
			endpointID, p.PublicKey, receivedAt.Unix(), p.RX, p.TX); err != nil {
			return err
		}
	}
	// Trim history beyond the retention window.
	cutoff := receivedAt.Add(-historyRetention).Unix()
	if _, err := tx.Exec(`DELETE FROM status_history WHERE report_ts < ?`, cutoff); err != nil {
		return err
	}
	return tx.Commit()
}

// historyRetention bounds how long per-peer samples are kept.
const historyRetention = 14 * 24 * time.Hour

// EndpointThroughput returns the per-peer transfer rate (bytes/s for rx and tx),
// computed from the two most recent reports of an endpoint. Keyed by public key.
func (s *Store) EndpointThroughput(endpointID int64) (map[string][2]int64, error) {
	var t1, t2 int64
	rows, err := s.db.Query(
		`SELECT DISTINCT report_ts FROM status_history WHERE endpoint_id=? ORDER BY report_ts DESC LIMIT 2`,
		endpointID)
	if err != nil {
		return nil, err
	}
	var ts []int64
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return nil, err
		}
		ts = append(ts, v)
	}
	rows.Close()
	if len(ts) < 2 {
		return map[string][2]int64{}, nil
	}
	t2, t1 = ts[0], ts[1] // t2 newest
	dt := t2 - t1
	if dt <= 0 {
		return map[string][2]int64{}, nil
	}

	type rt struct{ rx, tx int64 }
	at := func(ts int64) (map[string]rt, error) {
		m := map[string]rt{}
		r, err := s.db.Query(`SELECT public_key, rx, tx FROM status_history WHERE endpoint_id=? AND report_ts=?`, endpointID, ts)
		if err != nil {
			return nil, err
		}
		defer r.Close()
		for r.Next() {
			var k string
			var v rt
			if err := r.Scan(&k, &v.rx, &v.tx); err != nil {
				return nil, err
			}
			m[k] = v
		}
		return m, r.Err()
	}
	prev, err := at(t1)
	if err != nil {
		return nil, err
	}
	cur, err := at(t2)
	if err != nil {
		return nil, err
	}

	out := make(map[string][2]int64, len(cur))
	for k, c := range cur {
		if p, ok := prev[k]; ok {
			rx := (c.rx - p.rx) / dt
			tx := (c.tx - p.tx) / dt
			if rx < 0 {
				rx = 0 // counter reset
			}
			if tx < 0 {
				tx = 0
			}
			out[k] = [2]int64{rx, tx}
		}
	}
	return out, nil
}

// HistorySample is one stored report sample for a peer.
type HistorySample struct {
	TS time.Time
	RX int64
	TX int64
}

// PeerSeries returns up to n recent samples for a peer, oldest first.
func (s *Store) PeerSeries(endpointID int64, pubKey string, n int) ([]HistorySample, error) {
	rows, err := s.db.Query(
		`SELECT report_ts, rx, tx FROM status_history WHERE endpoint_id=? AND public_key=?
		 ORDER BY report_ts DESC LIMIT ?`, endpointID, pubKey, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HistorySample
	for rows.Next() {
		var h HistorySample
		var ts int64
		if err := rows.Scan(&ts, &h.RX, &h.TX); err != nil {
			return nil, err
		}
		h.TS = time.Unix(ts, 0)
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Reverse to oldest-first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// PeerFirstSeen returns the earliest recorded sample time for a peer.
func (s *Store) PeerFirstSeen(endpointID int64, pubKey string) (time.Time, bool, error) {
	var ts sql.NullInt64
	err := s.db.QueryRow(
		`SELECT MIN(report_ts) FROM status_history WHERE endpoint_id=? AND public_key=?`,
		endpointID, pubKey).Scan(&ts)
	if err != nil || !ts.Valid {
		return time.Time{}, false, err
	}
	return time.Unix(ts.Int64, 0), true, nil
}

// EndpointSeries returns up to n recent total-throughput samples (bytes/s,
// rx+tx summed across peers) for an endpoint, oldest first — for a sparkline.
func (s *Store) EndpointSeries(endpointID int64, n int) ([]int64, error) {
	rows, err := s.db.Query(
		`SELECT report_ts, SUM(rx+tx) FROM status_history WHERE endpoint_id=?
		 GROUP BY report_ts ORDER BY report_ts DESC LIMIT ?`, endpointID, n+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type pt struct{ ts, total int64 }
	var pts []pt
	for rows.Next() {
		var p pt
		if err := rows.Scan(&p.ts, &p.total); err != nil {
			return nil, err
		}
		pts = append(pts, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// pts is newest-first; reverse to oldest-first and derive per-interval rate.
	var rates []int64
	for i := len(pts) - 1; i > 0; i-- {
		dt := pts[i-1].ts - pts[i].ts
		if dt <= 0 {
			continue
		}
		d := (pts[i-1].total - pts[i].total) / dt
		if d < 0 {
			d = 0
		}
		rates = append(rates, d)
	}
	return rates, nil
}

func scanPeer(sc interface{ Scan(...any) error }) (StatusPeer, error) {
	var p StatusPeer
	var hs int64
	if err := sc.Scan(&p.EndpointID, &p.PublicKey, &hs, &p.RX, &p.TX, &p.RemoteEndpoint, &p.AllowedIPs); err != nil {
		return p, err
	}
	p.LastHandshake = time.Unix(hs, 0)
	return p, nil
}

const peerCols = `endpoint_id, public_key, last_handshake, rx, tx, remote_endpoint, allowed_ips`

// PeersForEndpoint returns the last reported peers for an endpoint.
func (s *Store) PeersForEndpoint(endpointID int64) ([]StatusPeer, error) {
	rows, err := s.db.Query(`SELECT `+peerCols+` FROM status_peer WHERE endpoint_id=?`, endpointID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StatusPeer
	for rows.Next() {
		p, err := scanPeer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PeersByKey returns every reported peer (across endpoints) for a public key.
func (s *Store) PeersByKey(pubKey string) ([]StatusPeer, error) {
	rows, err := s.db.Query(`SELECT `+peerCols+` FROM status_peer WHERE public_key=?`, pubKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StatusPeer
	for rows.Next() {
		p, err := scanPeer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// LastHandshakeByKey returns the most recent handshake reported for each public
// key, across all endpoints — for the whole fleet or, when ownerUID is non-empty,
// for that user's machines only. Listing pages use it to avoid one PeersByKey
// query per machine.
func (s *Store) LastHandshakeByKey(ownerUID string) (map[string]time.Time, error) {
	q := `SELECT public_key, MAX(last_handshake) FROM status_peer`
	var args []any
	if ownerUID != "" {
		q += ` WHERE public_key IN (SELECT public_key FROM machine WHERE owner_uid=?)`
		args = append(args, ownerUID)
	}
	q += ` GROUP BY public_key`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var k string
		var hs int64
		if err := rows.Scan(&k, &hs); err != nil {
			return nil, err
		}
		out[k] = time.Unix(hs, 0)
	}
	return out, rows.Err()
}

// LastReport returns the most recent report time for an endpoint, if any.
func (s *Store) LastReport(endpointID int64) (time.Time, bool, error) {
	var ts int64
	err := s.db.QueryRow(`SELECT received_at FROM status_report WHERE endpoint_id=?`, endpointID).Scan(&ts)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	return time.Unix(ts, 0), true, nil
}
