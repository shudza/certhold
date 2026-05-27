package db

import (
	"context"
	"fmt"
)

const schemaVersion = 4

// The peers table extends PLAN.md with authorized_key BLOB and created_at TIMESTAMP.
// We persist the peer's pubkey so certhold can re-sign certs on update/rekey without
// round-tripping to the peer to ask for it again.
//
// The base CREATE TABLE statements omit the T15 mode/target_user columns; they are
// added by addModeColumns() so a pre-T15 db file (schema_version=1) migrates without
// data loss. The DEFAULT 'root' on those columns means any rows that pre-date the
// migration retain the v1 on-disk layout, matching the existing /etc/ssh files there.
const schemaSQL = `
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS peers (
  name TEXT PRIMARY KEY,
  cert_serial INTEGER NOT NULL,
  pubkey_fingerprint TEXT NOT NULL,
  authorized_key BLOB NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL,
  last_krl_version INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS groups (
  name TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS peer_groups (
  peer_name TEXT NOT NULL REFERENCES peers(name),
  group_name TEXT NOT NULL REFERENCES groups(name),
  PRIMARY KEY (peer_name, group_name)
);

CREATE TABLE IF NOT EXISTS peer_allowed_groups (
  peer_name TEXT NOT NULL REFERENCES peers(name),
  group_name TEXT NOT NULL REFERENCES groups(name),
  PRIMARY KEY (peer_name, group_name)
);

CREATE TABLE IF NOT EXISTS tokens (
  token TEXT PRIMARY KEY,
  peer_name TEXT NOT NULL,
  groups TEXT NOT NULL,
  tarball BLOB,
  consumed INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS ca (
  version INTEGER PRIMARY KEY,
  active INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS krl_version (
  version INTEGER PRIMARY KEY,
  generated_at TIMESTAMP NOT NULL
);
`

func (db *DB) migrate(ctx context.Context) error {
	if _, err := db.sql.ExecContext(ctx, schemaSQL); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	if err := db.addModeColumns(ctx); err != nil {
		return err
	}
	if err := db.addTarballColumn(ctx); err != nil {
		return err
	}
	if err := db.addLayoutVersionColumn(ctx); err != nil {
		return err
	}
	if _, err := db.sql.ExecContext(ctx,
		`INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)`,
		fmt.Sprintf("%d", schemaVersion),
	); err != nil {
		return fmt.Errorf("insert schema_version: %w", err)
	}
	return nil
}

func (db *DB) addModeColumns(ctx context.Context) error {
	for _, t := range []string{"peers", "tokens"} {
		has, err := db.tableHasColumns(ctx, t)
		if err != nil {
			return err
		}
		if !has["mode"] {
			if _, err := db.sql.ExecContext(ctx,
				fmt.Sprintf(`ALTER TABLE %s ADD COLUMN mode TEXT NOT NULL DEFAULT 'root'`, t)); err != nil {
				return fmt.Errorf("alter %s add mode: %w", t, err)
			}
		}
		if !has["target_user"] {
			if _, err := db.sql.ExecContext(ctx,
				fmt.Sprintf(`ALTER TABLE %s ADD COLUMN target_user TEXT NOT NULL DEFAULT ''`, t)); err != nil {
				return fmt.Errorf("alter %s add target_user: %w", t, err)
			}
		}
	}
	return nil
}

func (db *DB) addTarballColumn(ctx context.Context) error {
	has, err := db.tableHasColumns(ctx, "tokens")
	if err != nil {
		return err
	}
	if !has["tarball"] {
		if _, err := db.sql.ExecContext(ctx,
			`ALTER TABLE tokens ADD COLUMN tarball BLOB`); err != nil {
			return fmt.Errorf("alter tokens add tarball: %w", err)
		}
	}
	return nil
}

func (db *DB) addLayoutVersionColumn(ctx context.Context) error {
	has, err := db.tableHasColumns(ctx, "peers")
	if err != nil {
		return err
	}
	if !has["layout_version"] {
		if _, err := db.sql.ExecContext(ctx,
			`ALTER TABLE peers ADD COLUMN layout_version INTEGER NOT NULL DEFAULT 1`); err != nil {
			return fmt.Errorf("alter peers add layout_version: %w", err)
		}
	}
	return nil
}

func (db *DB) tableHasColumns(ctx context.Context, table string) (map[string]bool, error) {
	rows, err := db.sql.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return nil, fmt.Errorf("pragma table_info(%s): %w", table, err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, fmt.Errorf("scan pragma: %w", err)
		}
		out[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iter pragma: %w", err)
	}
	return out, nil
}
