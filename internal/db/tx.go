package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Tx is a transaction-scoped handle exposing the subset of writes that callers
// need to commit atomically. Obtain one via DB.WithTx; every method runs
// against the same underlying *sql.Tx so a returned error rolls the whole unit
// back.
type Tx struct {
	tx *sql.Tx
}

// WithTx runs fn inside a single transaction. If fn returns an error (or
// panics) the transaction is rolled back; otherwise it is committed. fn must
// only touch the database through the provided *Tx.
func (db *DB) WithTx(ctx context.Context, fn func(*Tx) error) (err error) {
	sqlTx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = sqlTx.Rollback()
			panic(p)
		}
		if err != nil {
			_ = sqlTx.Rollback()
		}
	}()
	if err = fn(&Tx{tx: sqlTx}); err != nil {
		return err
	}
	if err = sqlTx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (t *Tx) InsertToken(ctx context.Context, token, peerName, groupsCSV, targetUser string, tarball []byte) error {
	_, err := t.tx.ExecContext(ctx,
		`INSERT INTO tokens(token, peer_name, groups, consumed, created_at, target_user, tarball) VALUES (?, ?, ?, 0, ?, ?, ?)`,
		token, peerName, groupsCSV, time.Now().UTC(), targetUser, tarball,
	)
	if err != nil {
		return fmt.Errorf("insert token: %w", err)
	}
	return nil
}

// InsertReenrollToken records a re-enroll token: an enrollment token for an
// EXISTING peer carrying, besides the tarball, the staged material ConsumeToken
// commits to the peer row at redemption. Until then the peer row is untouched.
func (t *Tx) InsertReenrollToken(ctx context.Context, token, peerName, groupsCSV, targetUser string, tarball []byte, staged StagedReenroll) error {
	var allowedCSV any
	if staged.AllowedSet {
		allowedCSV = strings.Join(staged.Allowed, ",")
	}
	_, err := t.tx.ExecContext(ctx,
		`INSERT INTO tokens(token, peer_name, groups, consumed, created_at, target_user, tarball,
		                    staged_authorized_key, staged_fingerprint, staged_serial, staged_cert,
		                    staged_pull_token, staged_inbound, staged_address, staged_allowed)
		 VALUES (?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		token, peerName, groupsCSV, time.Now().UTC(), targetUser, tarball,
		staged.AuthorizedKey, staged.Fingerprint, int64(staged.Serial), staged.Cert,
		staged.PullToken, boolToInt(staged.Inbound), staged.Address, allowedCSV,
	)
	if err != nil {
		return fmt.Errorf("insert re-enroll token: %w", err)
	}
	return nil
}

// DeleteUnconsumedPeerTokens supersedes any prior outstanding enrollment
// one-liners for the peer: minting a new token for the same peer invalidates
// every unconsumed one (they answer 404 afterwards), and deleting the rows also
// destroys their stored tarballs (each embeds a usable private key + cert).
func (t *Tx) DeleteUnconsumedPeerTokens(ctx context.Context, peerName string) error {
	if _, err := t.tx.ExecContext(ctx,
		`DELETE FROM tokens WHERE peer_name = ? AND consumed = 0`, peerName); err != nil {
		return fmt.Errorf("delete unconsumed peer tokens: %w", err)
	}
	return nil
}

func (t *Tx) InsertPeer(ctx context.Context, name string, serial uint64, fingerprint string, authorizedKey []byte, targetUser string, inbound bool, pullToken string) error {
	_, err := t.tx.ExecContext(ctx,
		`INSERT INTO peers(name, cert_serial, pubkey_fingerprint, authorized_key, revoked, created_at, target_user, inbound, pull_token)
		 VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?)`,
		name, int64(serial), fingerprint, authorizedKey, time.Now().UTC(), targetUser, boolToInt(inbound), pullToken,
	)
	if err != nil {
		return fmt.Errorf("insert peer: %w", err)
	}
	return nil
}

func (t *Tx) SetPeerCert(ctx context.Context, name string, cert []byte, serial uint64) error {
	res, err := t.tx.ExecContext(ctx,
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

func (t *Tx) SetPeerAddress(ctx context.Context, name, address string) error {
	res, err := t.tx.ExecContext(ctx, `UPDATE peers SET address = ? WHERE name = ?`, address, name)
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

func (t *Tx) EnsureGroup(ctx context.Context, name string) error {
	if _, err := t.tx.ExecContext(ctx, `INSERT OR IGNORE INTO groups(name) VALUES (?)`, name); err != nil {
		return fmt.Errorf("ensure group: %w", err)
	}
	return nil
}

func (t *Tx) SetPeerGroups(ctx context.Context, peer string, groups []string) error {
	return setPeerGroupsTableTx(ctx, t.tx, "peer_groups", peer, groups)
}

func (t *Tx) SetPeerAllowedGroups(ctx context.Context, peer string, groups []string) error {
	return setPeerGroupsTableTx(ctx, t.tx, "peer_allowed_groups", peer, groups)
}

func (t *Tx) CreateGroup(ctx context.Context, name string) error {
	return createGroupTx(ctx, t.tx, name)
}

func (t *Tx) DeleteGroup(ctx context.Context, name string) error {
	return deleteGroupTx(ctx, t.tx, name)
}

func (t *Tx) RenameGroup(ctx context.Context, oldName, newName string) error {
	return renameGroupTx(ctx, t.tx, oldName, newName)
}

func (t *Tx) GroupExists(ctx context.Context, name string) (bool, error) {
	return groupExistsTx(ctx, t.tx, name)
}

func (t *Tx) GetGroupMembers(ctx context.Context, name string) ([]string, error) {
	return getGroupPeersTx(ctx, t.tx, "peer_groups", name)
}

func (t *Tx) GetGroupAllowedBy(ctx context.Context, name string) ([]string, error) {
	return getGroupPeersTx(ctx, t.tx, "peer_allowed_groups", name)
}
