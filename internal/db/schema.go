package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"
)

const schemaVersion = 8

// The peers table extends PLAN.md with authorized_key BLOB and created_at TIMESTAMP.
// We persist the peer's pubkey so certhold can re-sign certs on update/rekey without
// round-tripping to the peer to ask for it again.
//
// The base CREATE TABLE statements plus the incremental add*Column migrations bring
// ANY db file (fresh or old) up to the historical schema_version=5 shape (all columns
// present). dropDeadColumns() then rebuilds peers/tokens to physically remove the
// vestigial mode/layout_version/last_krl_version columns and the dead krl_version
// table, leaving the clean single-user-mode schema (schema_version=6). Running the
// add* steps before the drop keeps the migration correct for both fresh and pre-existing
// databases without rewriting the base CREATE statements. addClientPeerColumns then
// adds the client-peer columns (inbound/pull_token/cert) on top of the rebuilt peers
// table (schema_version=7); it must run AFTER dropDeadColumns or the rebuild would
// discard them.
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
`

func (db *DB) migrate(ctx context.Context) error {
	if _, err := db.sql.ExecContext(ctx, schemaSQL); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	ver, err := db.storedSchemaVersion(ctx)
	if err != nil {
		return err
	}
	// Workaround for a destructive re-migration: addModeColumns re-adds the
	// dropped mode column on every open, which re-triggers the dropDeadColumns
	// rebuild and silently discards the post-v6 inbound/pull_token/cert values.
	// The legacy add*/drop steps therefore only run for databases below the
	// rebuilt v6 shape; addClientPeerColumns stays unconditional (presence-gated).
	if ver < 6 {
		if err := db.addModeColumns(ctx); err != nil {
			return err
		}
		if err := db.addTarballColumn(ctx); err != nil {
			return err
		}
		if err := db.addLayoutVersionColumn(ctx); err != nil {
			return err
		}
		if err := db.addAddressColumn(ctx); err != nil {
			return err
		}
		if err := db.dropDeadColumns(ctx); err != nil {
			return err
		}
	}
	if err := db.addClientPeerColumns(ctx); err != nil {
		return err
	}
	if err := db.addPushReachableColumn(ctx); err != nil {
		return err
	}
	if err := db.backfillActiveCAVersion(ctx); err != nil {
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

func (db *DB) addAddressColumn(ctx context.Context) error {
	has, err := db.tableHasColumns(ctx, "peers")
	if err != nil {
		return err
	}
	if !has["address"] {
		if _, err := db.sql.ExecContext(ctx,
			`ALTER TABLE peers ADD COLUMN address TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("alter peers add address: %w", err)
		}
	}
	return nil
}

func (db *DB) storedSchemaVersion(ctx context.Context) (int, error) {
	var raw string
	err := db.sql.QueryRowContext(ctx,
		`SELECT value FROM meta WHERE key = 'schema_version'`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read schema_version: %w", err)
	}
	ver, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("parse schema_version %q: %w", raw, err)
	}
	return ver, nil
}

func (db *DB) addClientPeerColumns(ctx context.Context) error {
	has, err := db.tableHasColumns(ctx, "peers")
	if err != nil {
		return err
	}
	if !has["inbound"] {
		if _, err := db.sql.ExecContext(ctx,
			`ALTER TABLE peers ADD COLUMN inbound INTEGER NOT NULL DEFAULT 1`); err != nil {
			return fmt.Errorf("alter peers add inbound: %w", err)
		}
	}
	if !has["pull_token"] {
		if _, err := db.sql.ExecContext(ctx,
			`ALTER TABLE peers ADD COLUMN pull_token TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("alter peers add pull_token: %w", err)
		}
	}
	if !has["cert"] {
		if _, err := db.sql.ExecContext(ctx,
			`ALTER TABLE peers ADD COLUMN cert BLOB`); err != nil {
			return fmt.Errorf("alter peers add cert: %w", err)
		}
	}
	return nil
}

// addPushReachableColumn adds peers.push_reachable (schema_version=8). It marks
// whether the manager can dial the peer back for pushes: captured at enroll
// time, set to 0 for a peer the manager cannot reach (firewall/NAT/down), so
// push paths skip it and route it onto the self-fetch (pull) channel instead.
// Existing rows DEFAULT 1, preserving the pre-feature behavior (every peer was
// assumed dialable); they get corrected on the next successful probe. It is
// presence-gated (idempotent) and unconditional, like addClientPeerColumns.
func (db *DB) addPushReachableColumn(ctx context.Context) error {
	has, err := db.tableHasColumns(ctx, "peers")
	if err != nil {
		return err
	}
	if !has["push_reachable"] {
		if _, err := db.sql.ExecContext(ctx,
			`ALTER TABLE peers ADD COLUMN push_reachable INTEGER NOT NULL DEFAULT 1`); err != nil {
			return fmt.Errorf("alter peers add push_reachable: %w", err)
		}
	}
	return nil
}

// dropDeadColumns physically removes the vestigial mode/layout_version/last_krl_version
// columns and the dead krl_version table left behind by the v1/root + KRL removal
// (T07/T08). SQLite cannot drop columns in place, so each table is rebuilt with the
// final schema. It is idempotent: once peers.mode is gone the whole step no-ops.
//
// Foreign keys (peer_groups/peer_allowed_groups -> peers(name)) are preserved by
// toggling PRAGMA foreign_keys OFF around the rebuild — a DROP TABLE peers with FKs
// enforced would otherwise be rejected or cascade. The pragma must be set outside any
// transaction (SQLite ignores it mid-transaction); MaxOpenConns(1) keeps it on the one
// connection. A post-rebuild foreign_key_check confirms membership rows still resolve.
func (db *DB) dropDeadColumns(ctx context.Context) error {
	peerCols, err := db.tableHasColumns(ctx, "peers")
	if err != nil {
		return err
	}
	if !peerCols["mode"] && !peerCols["layout_version"] && !peerCols["last_krl_version"] {
		return nil
	}

	if _, err := db.sql.ExecContext(ctx, `PRAGMA foreign_keys=OFF`); err != nil {
		return fmt.Errorf("disable foreign_keys: %w", err)
	}
	defer func() { _, _ = db.sql.ExecContext(ctx, `PRAGMA foreign_keys=ON`) }()

	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin drop dead columns: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
CREATE TABLE peers_new (
  name TEXT PRIMARY KEY,
  cert_serial INTEGER NOT NULL,
  pubkey_fingerprint TEXT NOT NULL,
  authorized_key BLOB NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL,
  target_user TEXT NOT NULL DEFAULT '',
  address TEXT NOT NULL DEFAULT ''
);
INSERT INTO peers_new(name, cert_serial, pubkey_fingerprint, authorized_key, revoked, created_at, target_user, address)
  SELECT name, cert_serial, pubkey_fingerprint, authorized_key, revoked, created_at, target_user, address FROM peers;
DROP TABLE peers;
ALTER TABLE peers_new RENAME TO peers;

CREATE TABLE tokens_new (
  token TEXT PRIMARY KEY,
  peer_name TEXT NOT NULL,
  groups TEXT NOT NULL,
  tarball BLOB,
  consumed INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL,
  target_user TEXT NOT NULL DEFAULT ''
);
INSERT INTO tokens_new(token, peer_name, groups, tarball, consumed, created_at, target_user)
  SELECT token, peer_name, groups, tarball, consumed, created_at, target_user FROM tokens;
DROP TABLE tokens;
ALTER TABLE tokens_new RENAME TO tokens;

DROP TABLE IF EXISTS krl_version;
`); err != nil {
		return fmt.Errorf("rebuild tables dropping dead columns: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit drop dead columns: %w", err)
	}

	rows, err := db.sql.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return fmt.Errorf("foreign_key_check: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return fmt.Errorf("foreign_key_check found violations after dropping dead columns")
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iter foreign_key_check: %w", err)
	}
	return nil
}

// backfillActiveCAVersion self-heals installs created before init learned to seed
// CA version 1: those databases have peers but an empty ca table, so the tui/serve
// "is this initialized?" gate (ActiveCAVersion) fails until their first rekey. The
// guards keep this safe and idempotent:
//   - peers exist  -> the DB was actually initialized (a never-init'd DB has no peers
//     and must not be backfilled; init itself seeds the row after this runs).
//   - ca table empty -> it predates the fix and never rekeyed (a rekeyed DB already
//     has a row; we never overwrite or duplicate it).
//
// It runs inline within migrate (during db.Open, before the DB struct is returned),
// matching InsertCAVersion's column layout and UTC created_at.
func (db *DB) backfillActiveCAVersion(ctx context.Context) error {
	var caRows, peerRows int
	if err := db.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM ca`).Scan(&caRows); err != nil {
		return fmt.Errorf("count ca rows: %w", err)
	}
	if caRows != 0 {
		return nil
	}
	if err := db.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM peers`).Scan(&peerRows); err != nil {
		return fmt.Errorf("count peers: %w", err)
	}
	if peerRows == 0 {
		return nil
	}
	if _, err := db.sql.ExecContext(ctx,
		`INSERT INTO ca(version, active, created_at) VALUES (1, 1, ?)`,
		time.Now().UTC(),
	); err != nil {
		return fmt.Errorf("backfill active ca version: %w", err)
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
