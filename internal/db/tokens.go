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

func (db *DB) LookupToken(ctx context.Context, token string) (string, string, bool, error) {
	var peerName, groupsCSV string
	var consumed int
	err := db.sql.QueryRowContext(ctx,
		`SELECT peer_name, groups, consumed FROM tokens WHERE token = ?`, token,
	).Scan(&peerName, &groupsCSV, &consumed)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", false, ErrTokenNotFound
		}
		return "", "", false, fmt.Errorf("lookup token: %w", err)
	}
	return peerName, groupsCSV, consumed != 0, nil
}

func (db *DB) ConsumeToken(ctx context.Context, token string) (string, string, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return "", "", fmt.Errorf("begin consume token: %w", err)
	}
	defer tx.Rollback()

	var peerName, groupsCSV string
	var consumed int
	err = tx.QueryRowContext(ctx,
		`SELECT peer_name, groups, consumed FROM tokens WHERE token = ?`, token,
	).Scan(&peerName, &groupsCSV, &consumed)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", ErrTokenNotFound
		}
		return "", "", fmt.Errorf("select token: %w", err)
	}
	if consumed != 0 {
		return "", "", ErrTokenAlreadyConsumed
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE tokens SET consumed = 1 WHERE token = ? AND consumed = 0`, token)
	if err != nil {
		return "", "", fmt.Errorf("update token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return "", "", fmt.Errorf("update token rows: %w", err)
	}
	if n == 0 {
		return "", "", ErrTokenAlreadyConsumed
	}
	if err := tx.Commit(); err != nil {
		return "", "", fmt.Errorf("commit consume token: %w", err)
	}
	return peerName, groupsCSV, nil
}
