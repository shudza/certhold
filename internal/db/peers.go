package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var ErrPeerNotFound = errors.New("peer not found")

const (
	ModeRoot = "root"
	ModeUser = "user"
)

type Peer struct {
	Name           string
	Serial         uint64
	Fingerprint    string
	AuthorizedKey  []byte
	Revoked        bool
	CreatedAt      time.Time
	LastKRLVersion int
	Mode           string
	TargetUser     string
	LayoutVersion  int
	Address        string
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

// InsertPeer keeps the original v1 signature for backward compatibility. The
// row's mode column receives its DEFAULT ('root'), matching the on-disk layout
// installed by pre-T15 code paths.
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

// InsertPeerWithMode is the T15+ entry point. mode must be one of ModeRoot or ModeUser.
// targetUser is informational; empty when mode == ModeRoot.
func (db *DB) InsertPeerWithMode(ctx context.Context, name string, serial uint64, fingerprint string, authorizedKey []byte, mode, targetUser string, layoutVersion int) error {
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO peers(name, cert_serial, pubkey_fingerprint, authorized_key, revoked, created_at, last_krl_version, mode, target_user, layout_version)
		 VALUES (?, ?, ?, ?, 0, ?, 0, ?, ?, ?)`,
		name, int64(serial), fingerprint, authorizedKey, time.Now().UTC(), mode, targetUser, layoutVersion,
	)
	if err != nil {
		return fmt.Errorf("insert peer: %w", err)
	}
	return nil
}

func (db *DB) GetPeer(ctx context.Context, name string) (*Peer, error) {
	row := db.sql.QueryRowContext(ctx,
		`SELECT name, cert_serial, pubkey_fingerprint, authorized_key, revoked, created_at, last_krl_version, mode, target_user, layout_version, address
		 FROM peers WHERE name = ?`, name)
	p := &Peer{}
	var serial int64
	var revoked int
	if err := row.Scan(&p.Name, &serial, &p.Fingerprint, &p.AuthorizedKey, &revoked, &p.CreatedAt, &p.LastKRLVersion, &p.Mode, &p.TargetUser, &p.LayoutVersion, &p.Address); err != nil {
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
		`SELECT name, cert_serial, pubkey_fingerprint, authorized_key, revoked, created_at, last_krl_version, mode, target_user, layout_version, address
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
		if err := rows.Scan(&p.Name, &serial, &p.Fingerprint, &p.AuthorizedKey, &revoked, &p.CreatedAt, &p.LastKRLVersion, &p.Mode, &p.TargetUser, &p.LayoutVersion, &p.Address); err != nil {
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
