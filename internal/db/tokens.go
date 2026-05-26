package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	ErrTokenNotFound        = errors.New("token not found")
	ErrTokenAlreadyConsumed = errors.New("token already consumed")
)

// InsertToken keeps the v1 signature. The token row's mode column gets its DEFAULT ('root').
func (db *DB) InsertToken(ctx context.Context, token, peerName, groupsCSV string) error {
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO tokens(token, peer_name, groups, consumed, created_at) VALUES (?, ?, ?, 0, ?)`,
		token, peerName, groupsCSV, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("insert token: %w", err)
	}
	return nil
}

// InsertTokenWithMode is the T15+ entry point. mode must be one of ModeRoot or ModeUser.
// tarball holds the pre-built install bundle signed at enroll-CLI time; nil is allowed
// (test-only paths) and scans back as a NULL BLOB.
func (db *DB) InsertTokenWithMode(ctx context.Context, token, peerName, groupsCSV, mode, targetUser string, tarball []byte) error {
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO tokens(token, peer_name, groups, consumed, created_at, mode, target_user, tarball) VALUES (?, ?, ?, 0, ?, ?, ?, ?)`,
		token, peerName, groupsCSV, time.Now().UTC(), mode, targetUser, tarball,
	)
	if err != nil {
		return fmt.Errorf("insert token: %w", err)
	}
	return nil
}

func (db *DB) LookupToken(ctx context.Context, token string) (peerName, groupsCSV, mode, targetUser string, consumed bool, err error) {
	var c int
	err = db.sql.QueryRowContext(ctx,
		`SELECT peer_name, groups, consumed, mode, target_user FROM tokens WHERE token = ?`, token,
	).Scan(&peerName, &groupsCSV, &c, &mode, &targetUser)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", "", "", false, ErrTokenNotFound
		}
		return "", "", "", "", false, fmt.Errorf("lookup token: %w", err)
	}
	return peerName, groupsCSV, mode, targetUser, c != 0, nil
}

func (db *DB) ConsumeToken(ctx context.Context, token string) (peerName, groupsCSV, mode, targetUser string, tarball []byte, err error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return "", "", "", "", nil, fmt.Errorf("begin consume token: %w", err)
	}
	defer tx.Rollback()

	var consumed int
	err = tx.QueryRowContext(ctx,
		`SELECT peer_name, groups, consumed, mode, target_user, tarball FROM tokens WHERE token = ?`, token,
	).Scan(&peerName, &groupsCSV, &consumed, &mode, &targetUser, &tarball)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", "", "", nil, ErrTokenNotFound
		}
		return "", "", "", "", nil, fmt.Errorf("select token: %w", err)
	}
	if consumed != 0 {
		return "", "", "", "", nil, ErrTokenAlreadyConsumed
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE tokens SET consumed = 1, tarball = NULL WHERE token = ? AND consumed = 0`, token)
	if err != nil {
		return "", "", "", "", nil, fmt.Errorf("update token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return "", "", "", "", nil, fmt.Errorf("update token rows: %w", err)
	}
	if n == 0 {
		return "", "", "", "", nil, ErrTokenAlreadyConsumed
	}
	if err := tx.Commit(); err != nil {
		return "", "", "", "", nil, fmt.Errorf("commit consume token: %w", err)
	}
	return peerName, groupsCSV, mode, targetUser, tarball, nil
}
