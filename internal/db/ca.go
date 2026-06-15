package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var ErrNoActiveCA = errors.New("no active ca version")

func (db *DB) InsertCAVersion(ctx context.Context, v int) error {
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO ca(version, active, created_at) VALUES (?, 0, ?)`,
		v, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("insert ca version: %w", err)
	}
	return nil
}

func (db *DB) ActiveCAVersion(ctx context.Context) (int, error) {
	var v int
	err := db.sql.QueryRowContext(ctx, `SELECT version FROM ca WHERE active = 1`).Scan(&v)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNoActiveCA
		}
		return 0, fmt.Errorf("active ca version: %w", err)
	}
	return v, nil
}

func (db *DB) CountCAVersions(ctx context.Context) (int, error) {
	var n int
	if err := db.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM ca`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count ca versions: %w", err)
	}
	return n, nil
}

func (db *DB) SetActiveCAVersion(ctx context.Context, v int) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin set active ca: %w", err)
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM ca WHERE version = ?`, v).Scan(&exists); err != nil {
		return fmt.Errorf("check ca version: %w", err)
	}
	if exists == 0 {
		return fmt.Errorf("set active ca: version %d does not exist", v)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE ca SET active = 0 WHERE active = 1`); err != nil {
		return fmt.Errorf("clear active ca: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE ca SET active = 1 WHERE version = ?`, v); err != nil {
		return fmt.Errorf("set active ca: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit set active ca: %w", err)
	}
	return nil
}
