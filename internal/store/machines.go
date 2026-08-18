package store

import (
	"database/sql"
	"errors"
	"time"
)

const machineCols = `id, owner_uid, name, public_key, address, status, created_at, approved_at, approved_by, owner_name`

func scanMachine(sc interface{ Scan(...any) error }) (*Machine, error) {
	var m Machine
	var created int64
	var approved sql.NullInt64
	if err := sc.Scan(&m.ID, &m.OwnerUID, &m.Name, &m.PublicKey, &m.Address,
		&m.Status, &created, &approved, &m.ApprovedBy, &m.OwnerName); err != nil {
		return nil, err
	}
	m.CreatedAt = time.Unix(created, 0)
	if approved.Valid {
		t := time.Unix(approved.Int64, 0)
		m.ApprovedAt = &t
	}
	return &m, nil
}

func (s *Store) CreateMachine(m *Machine) error {
	m.CreatedAt = time.Now()
	m.Status = StatusPending
	res, err := s.db.Exec(`
		INSERT INTO machine (owner_uid, owner_name, name, public_key, address, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		m.OwnerUID, m.OwnerName, m.Name, m.PublicKey, "", StatusPending, m.CreatedAt.Unix())
	if err != nil {
		return err
	}
	m.ID, err = res.LastInsertId()
	return err
}

func (s *Store) GetMachine(id int64) (*Machine, error) {
	row := s.db.QueryRow(`SELECT `+machineCols+` FROM machine WHERE id=?`, id)
	m, err := scanMachine(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return m, err
}

// UpdateMachineIdentity updates a machine's name and public key.
func (s *Store) UpdateMachineIdentity(id int64, name, publicKey string) error {
	_, err := s.db.Exec(`UPDATE machine SET name=?, public_key=? WHERE id=?`, name, publicKey, id)
	return err
}

// SetMachineAddress assigns an address to a machine (without changing status).
func (s *Store) SetMachineAddress(id int64, address string) error {
	_, err := s.db.Exec(`UPDATE machine SET address=? WHERE id=?`, address, id)
	return err
}

// CountPendingByOwner returns how many pending machines a user has.
func (s *Store) CountPendingByOwner(uid string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM machine WHERE owner_uid=? AND status=?`,
		uid, StatusPending).Scan(&n)
	return n, err
}

// DeleteExpiredPending removes pending machines created before cutoff and
// returns how many were deleted (frees their reserved address).
func (s *Store) DeleteExpiredPending(cutoff time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM machine WHERE status=? AND created_at < ?`,
		StatusPending, cutoff.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// SetMachinePending sends a machine back to pending (awaiting admin re-approval)
// while keeping its address and endpoint links so re-approval is one click.
func (s *Store) SetMachinePending(id int64) error {
	_, err := s.db.Exec(
		`UPDATE machine SET status=?, approved_at=NULL, approved_by='' WHERE id=?`,
		StatusPending, id)
	return err
}

// UpdateOwnerName refreshes the cached display name on all of a user's machines
// (called at login so it stays current and backfills older rows).
func (s *Store) UpdateOwnerName(uid, name string) error {
	_, err := s.db.Exec(`UPDATE machine SET owner_name=? WHERE owner_uid=?`, name, uid)
	return err
}

func (s *Store) MachineByPublicKey(pk string) (*Machine, error) {
	row := s.db.QueryRow(`SELECT `+machineCols+` FROM machine WHERE public_key=?`, pk)
	m, err := scanMachine(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return m, err
}

func (s *Store) ListMachinesByOwner(uid string) ([]*Machine, error) {
	return s.queryMachines(`SELECT `+machineCols+` FROM machine WHERE owner_uid=? ORDER BY created_at DESC`, uid)
}

func (s *Store) ListMachines() ([]*Machine, error) {
	return s.queryMachines(`SELECT ` + machineCols + ` FROM machine ORDER BY status='active', owner_uid, name`)
}

func (s *Store) queryMachines(q string, args ...any) ([]*Machine, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Machine
	for rows.Next() {
		m, err := scanMachine(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) DeleteMachine(id int64) error {
	_, err := s.db.Exec(`DELETE FROM machine WHERE id=?`, id)
	return err
}

// ApproveMachine assigns an address, links the endpoints and marks the machine
// active, all in one transaction. approvedBy records the acting administrator.
func (s *Store) ApproveMachine(id int64, address string, endpointIDs []int64, approvedBy string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now().Unix()
	if _, err := tx.Exec(`UPDATE machine SET address=?, status=?, approved_at=?, approved_by=? WHERE id=?`,
		address, StatusActive, now, approvedBy, id); err != nil {
		return err
	}
	if err := replaceEndpoints(tx, id, endpointIDs); err != nil {
		return err
	}
	return tx.Commit()
}

// SetMachineEndpoints updates the endpoint links of an already-active machine.
func (s *Store) SetMachineEndpoints(id int64, endpointIDs []int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := replaceEndpoints(tx, id, endpointIDs); err != nil {
		return err
	}
	return tx.Commit()
}

func replaceEndpoints(tx *sql.Tx, machineID int64, endpointIDs []int64) error {
	if _, err := tx.Exec(`DELETE FROM machine_endpoint WHERE machine_id=?`, machineID); err != nil {
		return err
	}
	for _, eid := range endpointIDs {
		if _, err := tx.Exec(`INSERT INTO machine_endpoint (machine_id, endpoint_id) VALUES (?, ?)`,
			machineID, eid); err != nil {
			return err
		}
	}
	return nil
}

// UsedAddresses returns every address currently assigned to a machine.
func (s *Store) UsedAddresses() ([]string, error) {
	rows, err := s.db.Query(`SELECT address FROM machine WHERE address <> ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// EndpointIDsForMachine returns the linked endpoint IDs.
func (s *Store) EndpointIDsForMachine(machineID int64) ([]int64, error) {
	rows, err := s.db.Query(`SELECT endpoint_id FROM machine_endpoint WHERE machine_id=?`, machineID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// EndpointLinks returns machine-to-endpoint links keyed by machine id, for the
// whole fleet or, when ownerUID is non-empty, for that user's machines only.
// Listing pages use it to avoid one EndpointIDsForMachine query per machine.
func (s *Store) EndpointLinks(ownerUID string) (map[int64][]int64, error) {
	q := `SELECT machine_id, endpoint_id FROM machine_endpoint`
	var args []any
	if ownerUID != "" {
		q += ` WHERE machine_id IN (SELECT id FROM machine WHERE owner_uid=?)`
		args = append(args, ownerUID)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]int64{}
	for rows.Next() {
		var mid, eid int64
		if err := rows.Scan(&mid, &eid); err != nil {
			return nil, err
		}
		out[mid] = append(out[mid], eid)
	}
	return out, rows.Err()
}

// EndpointsForMachine returns the full endpoint records linked to a machine.
func (s *Store) EndpointsForMachine(machineID int64) ([]*Endpoint, error) {
	rows, err := s.db.Query(`SELECT `+endpointCols+` FROM endpoint e
		WHERE e.id IN (SELECT endpoint_id FROM machine_endpoint WHERE machine_id=?)
		ORDER BY e.name`, machineID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Endpoint
	for rows.Next() {
		e, err := scanEndpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ActiveMachinesForEndpoint returns the active machines linked to an endpoint.
func (s *Store) ActiveMachinesForEndpoint(endpointID int64) ([]*Machine, error) {
	return s.queryMachines(`SELECT `+machineCols+` FROM machine
		WHERE status='active' AND id IN (SELECT machine_id FROM machine_endpoint WHERE endpoint_id=?)
		ORDER BY owner_uid, name`, endpointID)
}
