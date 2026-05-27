package db

import (
	"context"
	"database/sql"
	"fmt"
)

type GroupCount struct {
	Name      string
	PeerCount int
}

func (db *DB) ListGroupsWithPeerCount(ctx context.Context) ([]GroupCount, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT g.name, COUNT(pg.peer_name) FROM groups g
		 LEFT JOIN peer_groups pg ON pg.group_name = g.name
		 GROUP BY g.name ORDER BY g.name`)
	if err != nil {
		return nil, fmt.Errorf("list groups with peer count: %w", err)
	}
	defer rows.Close()
	var out []GroupCount
	for rows.Next() {
		var gc GroupCount
		if err := rows.Scan(&gc.Name, &gc.PeerCount); err != nil {
			return nil, fmt.Errorf("scan group count: %w", err)
		}
		out = append(out, gc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iter group counts: %w", err)
	}
	return out, nil
}

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
	if err := setPeerGroupsTableTx(ctx, tx, table, peer, groups); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit %s: %w", table, err)
	}
	return nil
}

// setPeerGroupsTableTx performs the delete-then-reinsert against an existing
// transaction so it can be composed into a larger atomic unit (enroll) or used
// standalone via setPeerGroupsTable.
func setPeerGroupsTableTx(ctx context.Context, tx *sql.Tx, table, peer string, groups []string) error {
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
