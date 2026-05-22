package db

import (
	"context"
	"fmt"
)

const schemaVersion = 1

// The peers table extends PLAN.md with authorized_key BLOB and created_at TIMESTAMP.
// We persist the peer's pubkey so certhold can re-sign certs on update/rekey without
// round-tripping to the peer to ask for it again.
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
	if _, err := db.sql.ExecContext(ctx,
		`INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', ?)`,
		fmt.Sprintf("%d", schemaVersion),
	); err != nil {
		return fmt.Errorf("insert schema_version: %w", err)
	}
	return nil
}
