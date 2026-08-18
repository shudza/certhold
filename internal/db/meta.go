package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
)

const (
	MetaInstanceKey = "instance_key"
	MetaFleetRev    = "fleet_rev"
	MetaSelfName    = "self_name"
)

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

// FleetRev returns the global fleet revision counter; a database that has never
// been bumped reports 0.
func (db *DB) FleetRev(ctx context.Context) (int64, error) {
	return fleetRevTx(ctx, db.sql)
}

// BumpFleetRev atomically increments the global fleet revision counter,
// creating it at 1 if absent.
func (db *DB) BumpFleetRev(ctx context.Context) error {
	return bumpFleetRevTx(ctx, db.sql)
}

func (t *Tx) FleetRev(ctx context.Context) (int64, error) {
	return fleetRevTx(ctx, t.tx)
}

func (t *Tx) BumpFleetRev(ctx context.Context) error {
	return bumpFleetRevTx(ctx, t.tx)
}

func fleetRevTx(ctx context.Context, q txCtx) (int64, error) {
	var value string
	if err := q.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, MetaFleetRev).Scan(&value); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, fmt.Errorf("get fleet_rev: %w", err)
	}
	rev, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse fleet_rev %q: %w", value, err)
	}
	return rev, nil
}

func bumpFleetRevTx(ctx context.Context, q txCtx) error {
	if _, err := q.ExecContext(ctx,
		`INSERT INTO meta(key, value) VALUES(?, '1')
		 ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + 1`,
		MetaFleetRev); err != nil {
		return fmt.Errorf("bump fleet_rev: %w", err)
	}
	return nil
}
