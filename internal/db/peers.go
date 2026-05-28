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
	Name          string
	Serial        uint64
	Fingerprint   string
	AuthorizedKey []byte
	Revoked       bool
	CreatedAt     time.Time
	TargetUser    string
	Address       string
}

// DialHost returns the network address certhold dials to reach this peer:
// the recorded Address when set, otherwise the peer Name. Every push path
// resolves the dial target through this so peers whose name is not a reachable
// hostname are still reachable.
func (p *Peer) DialHost() string {
	if p.Address != "" {
		return p.Address
	}
	return p.Name
}

// InsertPeer records a newly enrolled peer. targetUser is the install-time user
// whose ~/.ssh the peer's files land under (empty until redeemed, "root" for a
// --user root enrollment). The peer's network address is set separately via
// SetPeerAddress once known.
func (db *DB) InsertPeer(ctx context.Context, name string, serial uint64, fingerprint string, authorizedKey []byte, targetUser string) error {
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO peers(name, cert_serial, pubkey_fingerprint, authorized_key, revoked, created_at, target_user)
		 VALUES (?, ?, ?, ?, 0, ?, ?)`,
		name, int64(serial), fingerprint, authorizedKey, time.Now().UTC(), targetUser,
	)
	if err != nil {
		return fmt.Errorf("insert peer: %w", err)
	}
	return nil
}

func (db *DB) GetPeer(ctx context.Context, name string) (*Peer, error) {
	row := db.sql.QueryRowContext(ctx,
		`SELECT name, cert_serial, pubkey_fingerprint, authorized_key, revoked, created_at, target_user, address
		 FROM peers WHERE name = ?`, name)
	p := &Peer{}
	var serial int64
	var revoked int
	if err := row.Scan(&p.Name, &serial, &p.Fingerprint, &p.AuthorizedKey, &revoked, &p.CreatedAt, &p.TargetUser, &p.Address); err != nil {
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
		`SELECT name, cert_serial, pubkey_fingerprint, authorized_key, revoked, created_at, target_user, address
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
		if err := rows.Scan(&p.Name, &serial, &p.Fingerprint, &p.AuthorizedKey, &revoked, &p.CreatedAt, &p.TargetUser, &p.Address); err != nil {
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

// SetPeerTargetUser records the redeem-time user for a user-mode peer. The byte-server
// calls this when a ?user= install request consumes the token.
func (db *DB) SetPeerTargetUser(ctx context.Context, name, targetUser string) error {
	res, err := db.sql.ExecContext(ctx, `UPDATE peers SET target_user = ? WHERE name = ?`, targetUser, name)
	if err != nil {
		return fmt.Errorf("set peer target_user: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("set peer target_user rows: %w", err)
	}
	if n == 0 {
		return ErrPeerNotFound
	}
	return nil
}

// SetPeerAddress records the network address certhold dials to reach this peer.
// Mirrors SetPeerTargetUser; the enroll --address flag (via Tx.SetPeerAddress)
// and operator edits use it.
func (db *DB) SetPeerAddress(ctx context.Context, name, address string) error {
	res, err := db.sql.ExecContext(ctx, `UPDATE peers SET address = ? WHERE name = ?`, address, name)
	if err != nil {
		return fmt.Errorf("set peer address: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("set peer address rows: %w", err)
	}
	if n == 0 {
		return ErrPeerNotFound
	}
	return nil
}

// SetPeerAddressIfEmpty records address only when the peer has none yet, so an
// explicit address set at enroll time is never overwritten by the install-time
// source-IP backfill. Matching 0 rows (no peer, or address already set) is NOT
// an error.
func (db *DB) SetPeerAddressIfEmpty(ctx context.Context, name, address string) error {
	if _, err := db.sql.ExecContext(ctx, `UPDATE peers SET address = ? WHERE name = ? AND address = ''`, address, name); err != nil {
		return fmt.Errorf("set peer address if empty: %w", err)
	}
	return nil
}
