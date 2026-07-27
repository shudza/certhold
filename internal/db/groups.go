package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrGroupExists      = errors.New("group already exists")
	ErrGroupNotFound    = errors.New("group not found")
	ErrInvalidGroupName = errors.New("invalid group name")
)

// txCtx is the minimal interface satisfied by *sql.DB, *sql.Tx, and *sql.Conn
// for the read/write operations the group CRUD helpers need. It lets the *DB
// and *Tx variants share a single implementation.
type txCtx interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

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

// setPeerGroupsTableStrictTx is setPeerGroupsTableTx WITHOUT the ensure-create
// of missing groups: a group that no longer exists is an error, never an
// implicit re-creation. The re-enroll redemption commit uses it because its
// group list was validated at mint time, in an earlier transaction — a group
// deleted or renamed in between must fail the commit (rolling the consume
// back) rather than silently resurrect the group.
func setPeerGroupsTableStrictTx(ctx context.Context, tx *sql.Tx, table, peer string, groups []string) error {
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE peer_name = ?`, table), peer); err != nil {
		return fmt.Errorf("delete %s: %w", table, err)
	}
	for _, g := range groups {
		exists, err := groupExistsTx(ctx, tx, g)
		if err != nil {
			return fmt.Errorf("check group %s: %w", g, err)
		}
		if !exists {
			return fmt.Errorf("group %q no longer exists (deleted or renamed since the enroll was minted)", g)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s(peer_name, group_name) VALUES (?, ?)`, table), peer, g); err != nil {
			return fmt.Errorf("insert %s: %w", table, err)
		}
	}
	return nil
}

// CreateGroup inserts a new group and returns ErrGroupExists if the name is
// already taken, or ErrInvalidGroupName for an empty/whitespace name.
func (db *DB) CreateGroup(ctx context.Context, name string) error {
	return createGroupTx(ctx, db.sql, name)
}

func createGroupTx(ctx context.Context, q txCtx, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return ErrInvalidGroupName
	}
	exists, err := groupExistsTx(ctx, q, name)
	if err != nil {
		return err
	}
	if exists {
		return ErrGroupExists
	}
	if _, err := q.ExecContext(ctx, `INSERT INTO groups(name) VALUES (?)`, name); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return ErrGroupExists
		}
		return fmt.Errorf("create group: %w", err)
	}
	return nil
}

// DeleteGroup removes a group and its membership rows from peer_groups and
// peer_allowed_groups atomically. Returns ErrGroupNotFound if the group does
// not exist.
func (db *DB) DeleteGroup(ctx context.Context, name string) error {
	return db.WithTx(ctx, func(tx *Tx) error {
		return deleteGroupTx(ctx, tx.tx, name)
	})
}

func deleteGroupTx(ctx context.Context, q txCtx, name string) error {
	exists, err := groupExistsTx(ctx, q, name)
	if err != nil {
		return err
	}
	if !exists {
		return ErrGroupNotFound
	}
	if _, err := q.ExecContext(ctx, `DELETE FROM peer_groups WHERE group_name = ?`, name); err != nil {
		return fmt.Errorf("delete group memberships: %w", err)
	}
	if _, err := q.ExecContext(ctx, `DELETE FROM peer_allowed_groups WHERE group_name = ?`, name); err != nil {
		return fmt.Errorf("delete group allowed memberships: %w", err)
	}
	if _, err := q.ExecContext(ctx, `DELETE FROM groups WHERE name = ?`, name); err != nil {
		return fmt.Errorf("delete group: %w", err)
	}
	return nil
}

// RenameGroup atomically retargets every membership row from oldName to
// newName. Returns ErrGroupNotFound if oldName is missing, ErrGroupExists if
// newName is already taken, or ErrInvalidGroupName for an empty newName.
func (db *DB) RenameGroup(ctx context.Context, oldName, newName string) error {
	return db.WithTx(ctx, func(tx *Tx) error {
		return renameGroupTx(ctx, tx.tx, oldName, newName)
	})
}

func renameGroupTx(ctx context.Context, q txCtx, oldName, newName string) error {
	oldName = strings.TrimSpace(oldName)
	newName = strings.TrimSpace(newName)
	if newName == "" {
		return ErrInvalidGroupName
	}
	oldExists, err := groupExistsTx(ctx, q, oldName)
	if err != nil {
		return err
	}
	if !oldExists {
		return ErrGroupNotFound
	}
	if oldName != newName {
		newExists, err := groupExistsTx(ctx, q, newName)
		if err != nil {
			return err
		}
		if newExists {
			return ErrGroupExists
		}
	}
	if _, err := q.ExecContext(ctx, `INSERT OR IGNORE INTO groups(name) VALUES (?)`, newName); err != nil {
		return fmt.Errorf("rename insert new group: %w", err)
	}
	if _, err := q.ExecContext(ctx, `UPDATE peer_groups SET group_name = ? WHERE group_name = ?`, newName, oldName); err != nil {
		return fmt.Errorf("rename update peer_groups: %w", err)
	}
	if _, err := q.ExecContext(ctx, `UPDATE peer_allowed_groups SET group_name = ? WHERE group_name = ?`, newName, oldName); err != nil {
		return fmt.Errorf("rename update peer_allowed_groups: %w", err)
	}
	if oldName != newName {
		if _, err := q.ExecContext(ctx, `DELETE FROM groups WHERE name = ?`, oldName); err != nil {
			return fmt.Errorf("rename delete old group: %w", err)
		}
	}
	return nil
}

func (db *DB) GroupExists(ctx context.Context, name string) (bool, error) {
	return groupExistsTx(ctx, db.sql, name)
}

func groupExistsTx(ctx context.Context, q txCtx, name string) (bool, error) {
	var n int
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM groups WHERE name = ?`, name).Scan(&n); err != nil {
		return false, fmt.Errorf("group exists: %w", err)
	}
	return n > 0, nil
}

func (db *DB) GetGroupMembers(ctx context.Context, name string) ([]string, error) {
	return getGroupPeersTx(ctx, db.sql, "peer_groups", name)
}

func (db *DB) GetGroupAllowedBy(ctx context.Context, name string) ([]string, error) {
	return getGroupPeersTx(ctx, db.sql, "peer_allowed_groups", name)
}

func getGroupPeersTx(ctx context.Context, q txCtx, table, name string) ([]string, error) {
	rows, err := q.QueryContext(ctx,
		fmt.Sprintf(`SELECT peer_name FROM %s WHERE group_name = ? ORDER BY peer_name`, table), name)
	if err != nil {
		return nil, fmt.Errorf("query %s: %w", table, err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, fmt.Errorf("scan %s: %w", table, err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iter %s: %w", table, err)
	}
	return out, nil
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
