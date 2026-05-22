package db

import (
	"context"
	"fmt"
)

func (db *DB) EnsureGroup(ctx context.Context, name string) error {
	if _, err := db.sql.ExecContext(ctx, `INSERT OR IGNORE INTO groups(name) VALUES (?)`, name); err != nil {
		return fmt.Errorf("ensure group: %w", err)
	}
	return nil
}

func (db *DB) SetPeerGroups(ctx context.Context, peer string, groups []string) error {
	return db.setPeerGroupsTable(ctx, "peer_groups", peer, groups)
}

func (db *DB) GetPeerGroups(ctx context.Context, peer string) ([]string, error) {
	return db.getPeerGroupsTable(ctx, "peer_groups", peer)
}

func (db *DB) SetPeerAllowedGroups(ctx context.Context, peer string, groups []string) error {
	return db.setPeerGroupsTable(ctx, "peer_allowed_groups", peer, groups)
}

func (db *DB) GetPeerAllowedGroups(ctx context.Context, peer string) ([]string, error) {
	return db.getPeerGroupsTable(ctx, "peer_allowed_groups", peer)
}

func (db *DB) setPeerGroupsTable(ctx context.Context, table, peer string, groups []string) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin set %s: %w", table, err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE peer_name = ?`, table), peer); err != nil {
		return fmt.Errorf("delete %s: %w", table, err)
	}
	for _, g := range groups {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO groups(name) VALUES (?)`, g); err != nil {
			return fmt.Errorf("ensure group %s: %w", g, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s(peer_name, group_name) VALUES (?, ?)`, table), peer, g); err != nil {
			return fmt.Errorf("insert %s: %w", table, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit %s: %w", table, err)
	}
	return nil
}

func (db *DB) getPeerGroupsTable(ctx context.Context, table, peer string) ([]string, error) {
	rows, err := db.sql.QueryContext(ctx,
		fmt.Sprintf(`SELECT group_name FROM %s WHERE peer_name = ? ORDER BY group_name`, table), peer)
	if err != nil {
		return nil, fmt.Errorf("query %s: %w", table, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			return nil, fmt.Errorf("scan %s: %w", table, err)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iter %s: %w", table, err)
	}
	return out, nil
}
