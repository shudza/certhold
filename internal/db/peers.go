package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var ErrPeerNotFound = errors.New("peer not found")

type Peer struct {
	Name           string
	Serial         uint64
	Fingerprint    string
	AuthorizedKey  []byte
	Revoked        bool
	CreatedAt      time.Time
	LastKRLVersion int
}

func (db *DB) InsertPeer(ctx context.Context, name string, serial uint64, fingerprint string, authorizedKey []byte) error {
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO peers(name, cert_serial, pubkey_fingerprint, authorized_key, revoked, created_at, last_krl_version)
		 VALUES (?, ?, ?, ?, 0, ?, 0)`,
		name, int64(serial), fingerprint, authorizedKey, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("insert peer: %w", err)
	}
	return nil
}

func (db *DB) GetPeer(ctx context.Context, name string) (*Peer, error) {
	row := db.sql.QueryRowContext(ctx,
		`SELECT name, cert_serial, pubkey_fingerprint, authorized_key, revoked, created_at, last_krl_version
		 FROM peers WHERE name = ?`, name)
	p := &Peer{}
	var serial int64
	var revoked int
	if err := row.Scan(&p.Name, &serial, &p.Fingerprint, &p.AuthorizedKey, &revoked, &p.CreatedAt, &p.LastKRLVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrPeerNotFound
		}
		return nil, fmt.Errorf("get peer: %w", err)
	}
	p.Serial = uint64(serial)
	p.Revoked = revoked != 0
	return p, nil
}

func (db *DB) ListPeers(ctx context.Context) ([]Peer, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT name, cert_serial, pubkey_fingerprint, authorized_key, revoked, created_at, last_krl_version
		 FROM peers ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list peers: %w", err)
	}
	defer rows.Close()
	var out []Peer
	for rows.Next() {
		var p Peer
		var serial int64
		var revoked int
		if err := rows.Scan(&p.Name, &serial, &p.Fingerprint, &p.AuthorizedKey, &revoked, &p.CreatedAt, &p.LastKRLVersion); err != nil {
			return nil, fmt.Errorf("scan peer: %w", err)
		}
		p.Serial = uint64(serial)
		p.Revoked = revoked != 0
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iter peers: %w", err)
	}
	return out, nil
}

func (db *DB) SetPeerRevoked(ctx context.Context, name string) error {
	res, err := db.sql.ExecContext(ctx, `UPDATE peers SET revoked = 1 WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("set peer revoked: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("set peer revoked rows: %w", err)
	}
	if n == 0 {
		return ErrPeerNotFound
	}
	return nil
}

func (db *DB) UpdatePeerCertSerial(ctx context.Context, name string, serial uint64) error {
	res, err := db.sql.ExecContext(ctx, `UPDATE peers SET cert_serial = ? WHERE name = ?`, int64(serial), name)
	if err != nil {
		return fmt.Errorf("update peer cert_serial: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update peer cert_serial rows: %w", err)
	}
	if n == 0 {
		return ErrPeerNotFound
	}
	return nil
}

func (db *DB) UpdatePeerLastKRL(ctx context.Context, name string, version int) error {
	res, err := db.sql.ExecContext(ctx, `UPDATE peers SET last_krl_version = ? WHERE name = ?`, version, name)
	if err != nil {
		return fmt.Errorf("update peer last_krl_version: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update peer last_krl_version rows: %w", err)
	}
	if n == 0 {
		return ErrPeerNotFound
	}
	return nil
}
