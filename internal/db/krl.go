package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

func (db *DB) NextKRLVersion(ctx context.Context) (int, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin next krl: %w", err)
	}
	defer tx.Rollback()

	var maxV sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(version) FROM krl_version`).Scan(&maxV); err != nil {
		return 0, fmt.Errorf("max krl version: %w", err)
	}
	next := 1
	if maxV.Valid {
		next = int(maxV.Int64) + 1
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO krl_version(version, generated_at) VALUES (?, ?)`,
		next, time.Now().UTC(),
	); err != nil {
		return 0, fmt.Errorf("insert krl version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit next krl: %w", err)
	}
	return next, nil
}
