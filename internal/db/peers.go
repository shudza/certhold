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
	Inbound       bool
	PullToken     string
	Cert          []byte
	// PushReachable is whether the manager can dial this peer back for pushes.
	// False routes the peer onto the self-fetch (pull) channel: push paths skip
	// dialing it (like a client-style peer) until reachability returns.
	PushReachable bool
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
// --user root enrollment). inbound marks whether other peers may SSH into this
// one; pullToken is the standing token a client-style peer presents to pull
// refreshed material (empty for push-managed peers). The peer's network address
// is set separately via SetPeerAddress once known.
func (db *DB) InsertPeer(ctx context.Context, name string, serial uint64, fingerprint string, authorizedKey []byte, targetUser string, inbound bool, pullToken string) error {
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO peers(name, cert_serial, pubkey_fingerprint, authorized_key, revoked, created_at, target_user, inbound, pull_token)
		 VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?)`,
		name, int64(serial), fingerprint, authorizedKey, time.Now().UTC(), targetUser, boolToInt(inbound), pullToken,
	)
	if err != nil {
		return fmt.Errorf("insert peer: %w", err)
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

const peerColumns = `name, cert_serial, pubkey_fingerprint, authorized_key, revoked, created_at, target_user, address, inbound, pull_token, cert, push_reachable`

func scanPeer(row interface{ Scan(dest ...any) error }) (*Peer, error) {
	p := &Peer{}
	var serial int64
	var revoked, inbound, pushReachable int
	if err := row.Scan(&p.Name, &serial, &p.Fingerprint, &p.AuthorizedKey, &revoked, &p.CreatedAt, &p.TargetUser, &p.Address, &inbound, &p.PullToken, &p.Cert, &pushReachable); err != nil {
		return nil, err
	}
	p.Serial = uint64(serial)
	p.Revoked = revoked != 0
	p.Inbound = inbound != 0
	p.PushReachable = pushReachable != 0
	return p, nil
}

func (db *DB) GetPeer(ctx context.Context, name string) (*Peer, error) {
	row := db.sql.QueryRowContext(ctx,
		`SELECT `+peerColumns+` FROM peers WHERE name = ?`, name)
	p, err := scanPeer(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrPeerNotFound
		}
		return nil, fmt.Errorf("get peer: %w", err)
	}
	return p, nil
}

// GetPeerByPullToken resolves the peer holding the given standing pull token.
// An empty token is always not-found: the empty string is the column default for every
// push-managed peer, so matching it would hand out an arbitrary peer.
func (db *DB) GetPeerByPullToken(ctx context.Context, token string) (*Peer, error) {
	if token == "" {
		return nil, ErrPeerNotFound
	}
	row := db.sql.QueryRowContext(ctx,
		`SELECT `+peerColumns+` FROM peers WHERE pull_token = ?`, token)
	p, err := scanPeer(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrPeerNotFound
		}
		return nil, fmt.Errorf("get peer by pull token: %w", err)
	}
	return p, nil
}

func (db *DB) ListPeers(ctx context.Context) ([]Peer, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT `+peerColumns+` FROM peers ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list peers: %w", err)
	}
	defer rows.Close()
	var out []Peer
	for rows.Next() {
		p, err := scanPeer(rows)
		if err != nil {
			return nil, fmt.Errorf("scan peer: %w", err)
		}
		out = append(out, *p)
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

// DeletePeer hard-removes a peer and every row that references it — its
// group-membership rows (peer_groups), allowed-inbound rows
// (peer_allowed_groups), and any enrollment tokens (tokens.peer_name) — in a
// single transaction so no partial delete can occur. Returns ErrPeerNotFound if
// no peer with that name exists, mirroring GetPeer's not-found contract.
func (db *DB) DeletePeer(ctx context.Context, name string) error {
	return db.WithTx(ctx, func(tx *Tx) error {
		return deletePeerTx(ctx, tx.tx, name)
	})
}

func deletePeerTx(ctx context.Context, q txCtx, name string) error {
	if _, err := q.ExecContext(ctx, `DELETE FROM peer_groups WHERE peer_name = ?`, name); err != nil {
		return fmt.Errorf("delete peer groups: %w", err)
	}
	if _, err := q.ExecContext(ctx, `DELETE FROM peer_allowed_groups WHERE peer_name = ?`, name); err != nil {
		return fmt.Errorf("delete peer allowed groups: %w", err)
	}
	if _, err := q.ExecContext(ctx, `DELETE FROM tokens WHERE peer_name = ?`, name); err != nil {
		return fmt.Errorf("delete peer tokens: %w", err)
	}
	res, err := q.ExecContext(ctx, `DELETE FROM peers WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("delete peer: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete peer rows: %w", err)
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

// SetPeerCert stores the peer's latest signed certificate (public material)
// together with its serial so the two never drift apart.
func (db *DB) SetPeerCert(ctx context.Context, name string, cert []byte, serial uint64) error {
	res, err := db.sql.ExecContext(ctx,
		`UPDATE peers SET cert = ?, cert_serial = ? WHERE name = ?`, cert, int64(serial), name)
	if err != nil {
		return fmt.Errorf("set peer cert: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("set peer cert rows: %w", err)
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

// SetPeerInbound flips whether other peers may SSH into this one. T147's
// make-client flow sets it false (inbound -> client) after the peer's
// authorized_keys has been stripped of the CA trust line. Matching 0 rows is
// the peer-not-found error so callers can map it.
func (db *DB) SetPeerInbound(ctx context.Context, name string, inbound bool) error {
	res, err := db.sql.ExecContext(ctx, `UPDATE peers SET inbound = ? WHERE name = ?`, boolToInt(inbound), name)
	if err != nil {
		return fmt.Errorf("set peer inbound: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("set peer inbound rows: %w", err)
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

// SetPeerReachable records whether the manager can dial this peer back for
// pushes. The enroll-time probe sets it (1 on a successful capture dial, 0 when
// the manager cannot reach the peer); push paths route an unreachable peer onto
// the self-fetch channel. Matching 0 rows (no such peer) is NOT an error: the
// background probe may race a revoke/delete.
func (db *DB) SetPeerReachable(ctx context.Context, name string, reachable bool) error {
	if _, err := db.sql.ExecContext(ctx,
		`UPDATE peers SET push_reachable = ? WHERE name = ?`, boolToInt(reachable), name); err != nil {
		return fmt.Errorf("set peer reachable: %w", err)
	}
	return nil
}
