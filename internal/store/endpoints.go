package store

import (
	"database/sql"
	"errors"
	"time"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

func (s *Store) CreateEndpoint(e *Endpoint) error {
	e.CreatedAt = time.Now()
	res, err := s.db.Exec(`
		INSERT INTO endpoint (name, public_key, host_port, allowed_ips, dns, mtu,
		                      persistent_keepalive, tunnel_ip, upload_token, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Name, e.PublicKey, e.HostPort, e.AllowedIPs, e.DNS, e.MTU,
		e.PersistentKeepalive, e.TunnelIP, e.UploadToken, e.CreatedAt.Unix())
	if err != nil {
		return err
	}
	e.ID, err = res.LastInsertId()
	return err
}

func (s *Store) UpdateEndpoint(e *Endpoint) error {
	_, err := s.db.Exec(`
		UPDATE endpoint SET name=?, public_key=?, host_port=?, allowed_ips=?, dns=?,
		                    mtu=?, persistent_keepalive=?, tunnel_ip=?
		WHERE id=?`,
		e.Name, e.PublicKey, e.HostPort, e.AllowedIPs, e.DNS, e.MTU,
		e.PersistentKeepalive, e.TunnelIP, e.ID)
	return err
}

func (s *Store) DeleteEndpoint(id int64) error {
	_, err := s.db.Exec(`DELETE FROM endpoint WHERE id=?`, id)
	return err
}

// SetEndpointToken replaces an endpoint's upload token.
func (s *Store) SetEndpointToken(id int64, token string) error {
	_, err := s.db.Exec(`UPDATE endpoint SET upload_token=? WHERE id=?`, token, id)
	return err
}

func scanEndpoint(sc interface{ Scan(...any) error }) (*Endpoint, error) {
	var e Endpoint
	var created int64
	if err := sc.Scan(&e.ID, &e.Name, &e.PublicKey, &e.HostPort, &e.AllowedIPs,
		&e.DNS, &e.MTU, &e.PersistentKeepalive, &e.TunnelIP, &e.UploadToken, &created); err != nil {
		return nil, err
	}
	e.CreatedAt = time.Unix(created, 0)
	return &e, nil
}

const endpointCols = `id, name, public_key, host_port, allowed_ips, dns, mtu,
	persistent_keepalive, tunnel_ip, upload_token, created_at`

func (s *Store) GetEndpoint(id int64) (*Endpoint, error) {
	row := s.db.QueryRow(`SELECT `+endpointCols+` FROM endpoint WHERE id=?`, id)
	e, err := scanEndpoint(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}

func (s *Store) EndpointByName(name string) (*Endpoint, error) {
	row := s.db.QueryRow(`SELECT `+endpointCols+` FROM endpoint WHERE name=?`, name)
	e, err := scanEndpoint(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}

func (s *Store) EndpointByToken(token string) (*Endpoint, error) {
	row := s.db.QueryRow(`SELECT `+endpointCols+` FROM endpoint WHERE upload_token=?`, token)
	e, err := scanEndpoint(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}

func (s *Store) ListEndpoints() ([]*Endpoint, error) {
	rows, err := s.db.Query(`SELECT ` + endpointCols + ` FROM endpoint ORDER BY name`)
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
