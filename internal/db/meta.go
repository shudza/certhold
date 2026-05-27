package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

const MetaInstanceKey = "instance_key"

func (db *DB) GetMeta(ctx context.Context, key string) (value string, ok bool, err error) {
	row := db.sql.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key)
	if err := row.Scan(&value); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("get meta %q: %w", key, err)
	}
	return value, true, nil
}

func (db *DB) SetMeta(ctx context.Context, key, value string) error {
	if _, err := db.sql.ExecContext(ctx,
		`INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)`, key, value); err != nil {
		return fmt.Errorf("set meta %q: %w", key, err)
	}
	return nil
}
