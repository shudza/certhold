package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrTokenNotFound        = errors.New("token not found")
	ErrTokenAlreadyConsumed = errors.New("token already consumed")
)

// InsertToken records an enrollment token. targetUser is the install-time user the
// token redeems for (empty when unset). tarball holds the pre-built install bundle
// signed at enroll-CLI time; nil is allowed (test-only paths) and scans back as a
// NULL BLOB.
func (db *DB) InsertToken(ctx context.Context, token, peerName, groupsCSV, targetUser string, tarball []byte) error {
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO tokens(token, peer_name, groups, consumed, created_at, target_user, tarball) VALUES (?, ?, ?, 0, ?, ?, ?)`,
		token, peerName, groupsCSV, time.Now().UTC(), targetUser, tarball,
	)
	if err != nil {
		return fmt.Errorf("insert token: %w", err)
	}
	return nil
}

func (db *DB) LookupToken(ctx context.Context, token string) (peerName, groupsCSV, targetUser string, consumed bool, err error) {
	var c int
	err = db.sql.QueryRowContext(ctx,
		`SELECT peer_name, groups, consumed, target_user FROM tokens WHERE token = ?`, token,
	).Scan(&peerName, &groupsCSV, &c, &targetUser)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", "", false, ErrTokenNotFound
		}
		return "", "", "", false, fmt.Errorf("lookup token: %w", err)
	}
	return peerName, groupsCSV, targetUser, c != 0, nil
}

// StagedReenroll is the material a re-enroll of an existing peer stages on its
// token row at mint. The peer row is untouched until the token is consumed;
// ConsumeToken then commits every field here (plus the token's groups CSV) to
// the peer row in the same transaction that marks the token consumed, so a
// commit failure leaves the token redeemable and the peer unchanged. An empty
// Address means "keep the peer's current address".
type StagedReenroll struct {
	AuthorizedKey []byte
	Fingerprint   string
	Serial        uint64
	Cert          []byte
	PullToken     string
	Inbound       bool
	Address       string
	// Allowed is an explicitly chosen allowed-inbound set, honored at commit
	// only when AllowedSet is true; otherwise the commit preserves an inbound
	// peer's current allowed set (or seeds allowed = groups on a
	// client->inbound transition).
	Allowed    []string
	AllowedSet bool
}

// ConsumeToken atomically redeems an enrollment token: it checks the row is
// still unconsumed, marks it consumed and nulls the tarball. For a re-enroll
// token (staged material present) it additionally commits the staged material
// to the peer row — key, cert+serial, pull token, inbound flag, optional
// address, group membership, allowed-group transitions — and bumps fleet_rev,
// all in the same transaction: either the token stays redeemable and the live
// peer's row is byte-identical, or the whole new configuration is committed.
func (db *DB) ConsumeToken(ctx context.Context, token string) (peerName, groupsCSV, targetUser string, tarball []byte, err error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return "", "", "", nil, fmt.Errorf("begin consume token: %w", err)
	}
	defer tx.Rollback()

	var consumed int
	var staged StagedReenroll
	var stagedSerial int64
	var stagedInbound int
	var stagedAllowed sql.NullString
	err = tx.QueryRowContext(ctx,
		`SELECT peer_name, groups, consumed, target_user, tarball,
		        staged_authorized_key, staged_fingerprint, staged_serial, staged_cert,
		        staged_pull_token, staged_inbound, staged_address, staged_allowed
		 FROM tokens WHERE token = ?`, token,
	).Scan(&peerName, &groupsCSV, &consumed, &targetUser, &tarball,
		&staged.AuthorizedKey, &staged.Fingerprint, &stagedSerial, &staged.Cert,
		&staged.PullToken, &stagedInbound, &staged.Address, &stagedAllowed)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", "", nil, ErrTokenNotFound
		}
		return "", "", "", nil, fmt.Errorf("select token: %w", err)
	}
	if consumed != 0 {
		return "", "", "", nil, ErrTokenAlreadyConsumed
	}
	staged.Serial = uint64(stagedSerial)
	staged.Inbound = stagedInbound != 0
	staged.AllowedSet = stagedAllowed.Valid
	staged.Allowed = splitGroupsCSV(stagedAllowed.String)

	res, err := tx.ExecContext(ctx,
		`UPDATE tokens SET consumed = 1, tarball = NULL,
		        staged_authorized_key = NULL, staged_fingerprint = '', staged_serial = 0,
		        staged_cert = NULL, staged_pull_token = '', staged_address = '', staged_allowed = NULL
		 WHERE token = ? AND consumed = 0`, token)
	if err != nil {
		return "", "", "", nil, fmt.Errorf("update token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return "", "", "", nil, fmt.Errorf("update token rows: %w", err)
	}
	if n == 0 {
		return "", "", "", nil, ErrTokenAlreadyConsumed
	}

	if staged.AuthorizedKey != nil {
		if err := commitStagedReenroll(ctx, tx, peerName, groupsCSV, staged); err != nil {
			return "", "", "", nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return "", "", "", nil, fmt.Errorf("commit consume token: %w", err)
	}
	return peerName, groupsCSV, targetUser, tarball, nil
}

// commitStagedReenroll applies a re-enroll token's staged material to the peer
// row inside the consume transaction. Group membership becomes the token's
// mint-time groups (matching the staged cert's principals) via a STRICT insert:
// a group deleted or renamed since the mint fails the whole consume (the token
// stays redeemable and the operator re-mints), never an implicit re-creation.
// A peer revoked since the mint is refused for the same reason. The allowed set
// is only touched on an inbound transition: cleared when the peer becomes a
// client, seeded symmetric with the groups when a client becomes inbound;
// an inbound-to-inbound re-enroll preserves any allow-list curation done since
// enrollment (and since the install script leaves an already-present trust
// line alone, the peer file agrees).
func commitStagedReenroll(ctx context.Context, tx *sql.Tx, peerName, groupsCSV string, staged StagedReenroll) error {
	var wasInbound, wasRevoked int
	if err := tx.QueryRowContext(ctx,
		`SELECT inbound, revoked FROM peers WHERE name = ?`, peerName).Scan(&wasInbound, &wasRevoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("commit re-enroll: peer %q: %w", peerName, ErrPeerNotFound)
		}
		return fmt.Errorf("commit re-enroll: read peer state: %w", err)
	}
	if wasRevoked != 0 {
		return fmt.Errorf("commit re-enroll: peer %q was revoked after this enroll was minted; refusing to reconfigure a revoked peer", peerName)
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE peers SET authorized_key = ?, pubkey_fingerprint = ?, cert = ?, cert_serial = ?,
		        pull_token = ?, inbound = ?
		 WHERE name = ?`,
		staged.AuthorizedKey, staged.Fingerprint, staged.Cert, int64(staged.Serial),
		staged.PullToken, boolToInt(staged.Inbound), peerName); err != nil {
		return fmt.Errorf("commit re-enroll: update peer: %w", err)
	}
	if staged.Address != "" {
		if _, err := tx.ExecContext(ctx,
			`UPDATE peers SET address = ? WHERE name = ?`, staged.Address, peerName); err != nil {
			return fmt.Errorf("commit re-enroll: update address: %w", err)
		}
	}

	groups := splitGroupsCSV(groupsCSV)
	if err := setPeerGroupsTableStrictTx(ctx, tx, "peer_groups", peerName, groups); err != nil {
		return fmt.Errorf("commit re-enroll: set groups: %w", err)
	}
	switch {
	case !staged.Inbound:
		if err := setPeerGroupsTableStrictTx(ctx, tx, "peer_allowed_groups", peerName, nil); err != nil {
			return fmt.Errorf("commit re-enroll: clear allowed groups: %w", err)
		}
	case staged.AllowedSet:
		if err := setPeerGroupsTableStrictTx(ctx, tx, "peer_allowed_groups", peerName, staged.Allowed); err != nil {
			return fmt.Errorf("commit re-enroll: set allowed groups: %w", err)
		}
	case wasInbound == 0:
		if err := setPeerGroupsTableStrictTx(ctx, tx, "peer_allowed_groups", peerName, groups); err != nil {
			return fmt.Errorf("commit re-enroll: set allowed groups: %w", err)
		}
	}

	if err := bumpFleetRevTx(ctx, tx); err != nil {
		return fmt.Errorf("commit re-enroll: %w", err)
	}
	return nil
}

func splitGroupsCSV(csv string) []string {
	var out []string
	for _, g := range strings.Split(csv, ",") {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	return out
}
