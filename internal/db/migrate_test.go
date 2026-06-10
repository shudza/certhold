package db

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

const v2SchemaSQL = `
CREATE TABLE meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE peers (
  name TEXT PRIMARY KEY,
  cert_serial INTEGER NOT NULL,
  pubkey_fingerprint TEXT NOT NULL,
  authorized_key BLOB NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL,
  last_krl_version INTEGER NOT NULL DEFAULT 0,
  mode TEXT NOT NULL DEFAULT 'root',
  target_user TEXT NOT NULL DEFAULT ''
);
CREATE TABLE tokens (
  token TEXT PRIMARY KEY,
  peer_name TEXT NOT NULL,
  groups TEXT NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL,
  mode TEXT NOT NULL DEFAULT 'root',
  target_user TEXT NOT NULL DEFAULT ''
);
`

func openV2DB(t *testing.T, path string) *sql.DB {
	t.Helper()
	raw, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	raw.SetMaxOpenConns(1)
	ctx := context.Background()
	if _, err := raw.ExecContext(ctx, v2SchemaSQL); err != nil {
		t.Fatalf("apply v2 schema: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO meta(key, value) VALUES('schema_version', '2')`); err != nil {
		t.Fatalf("set schema_version=2: %v", err)
	}
	now := time.Now().UTC()
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO peers(name, cert_serial, pubkey_fingerprint, authorized_key, created_at)
		 VALUES('alpha', 7, 'SHA256:abc', ?, ?)`,
		[]byte("ssh-ed25519 AAAA-alpha"), now); err != nil {
		t.Fatalf("insert v2 peer: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO tokens(token, peer_name, groups, created_at)
		 VALUES('tok-v2', 'alpha', 'infra,db', ?)`, now); err != nil {
		t.Fatalf("insert v2 token: %v", err)
	}
	return raw
}

func TestMigratePreV3AddsTarballColumnPreservingRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v2.sqlite")
	raw := openV2DB(t, path)

	ctx := context.Background()
	if cols, err := (&DB{sql: raw}).tableHasColumns(ctx, "tokens"); err != nil {
		t.Fatalf("tableHasColumns: %v", err)
	} else if cols["tarball"] {
		t.Fatal("test precondition: v2 tokens table must NOT have a tarball column")
	}

	d := &DB{sql: raw}
	if err := d.migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	cols, err := d.tableHasColumns(ctx, "tokens")
	if err != nil {
		t.Fatalf("tableHasColumns after migrate: %v", err)
	}
	if !cols["tarball"] {
		t.Error("tarball column missing after migrate")
	}

	var notnull int
	var dflt any
	found := false
	rows, err := raw.QueryContext(ctx, "PRAGMA table_info(tokens)")
	if err != nil {
		t.Fatalf("pragma: %v", err)
	}
	for rows.Next() {
		var cid, nn, pk int
		var name, ctype string
		var dv any
		if err := rows.Scan(&cid, &name, &ctype, &nn, &dv, &pk); err != nil {
			t.Fatalf("scan pragma: %v", err)
		}
		if name == "tarball" {
			found = true
			notnull = nn
			dflt = dv
		}
	}
	rows.Close()
	if !found {
		t.Fatal("tarball column not reported by PRAGMA")
	}
	if notnull != 0 {
		t.Errorf("tarball column should be nullable (notnull=0), got notnull=%d", notnull)
	}
	if dflt != nil {
		t.Errorf("tarball column should have no default, got %v", dflt)
	}

	p, err := d.GetPeer(ctx, "alpha")
	if err != nil {
		t.Fatalf("GetPeer after migrate: %v", err)
	}
	if p.Serial != 7 || p.Fingerprint != "SHA256:abc" || string(p.AuthorizedKey) != "ssh-ed25519 AAAA-alpha" {
		t.Errorf("peer row not preserved: %+v", p)
	}

	peer, groups, tu, consumed, err := d.LookupToken(ctx, "tok-v2")
	if err != nil {
		t.Fatalf("LookupToken after migrate: %v", err)
	}
	if peer != "alpha" || groups != "infra,db" || tu != "" || consumed {
		t.Errorf("token row not preserved: peer=%q groups=%q tu=%q consumed=%v", peer, groups, tu, consumed)
	}

	var ver string
	if err := raw.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='schema_version'`).Scan(&ver); err != nil {
		t.Fatalf("read schema_version: %v", err)
	}
	if ver != "7" {
		t.Errorf("schema_version = %q, want \"7\"", ver)
	}

	if err := raw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

const v3SchemaSQL = `
CREATE TABLE meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE peers (
  name TEXT PRIMARY KEY,
  cert_serial INTEGER NOT NULL,
  pubkey_fingerprint TEXT NOT NULL,
  authorized_key BLOB NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL,
  last_krl_version INTEGER NOT NULL DEFAULT 0,
  mode TEXT NOT NULL DEFAULT 'root',
  target_user TEXT NOT NULL DEFAULT ''
);
CREATE TABLE tokens (
  token TEXT PRIMARY KEY,
  peer_name TEXT NOT NULL,
  groups TEXT NOT NULL,
  tarball BLOB,
  consumed INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL,
  mode TEXT NOT NULL DEFAULT 'root',
  target_user TEXT NOT NULL DEFAULT ''
);
`

func openV3DB(t *testing.T, path string) *sql.DB {
	t.Helper()
	raw, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	raw.SetMaxOpenConns(1)
	ctx := context.Background()
	if _, err := raw.ExecContext(ctx, v3SchemaSQL); err != nil {
		t.Fatalf("apply v3 schema: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO meta(key, value) VALUES('schema_version', '3')`); err != nil {
		t.Fatalf("set schema_version=3: %v", err)
	}
	now := time.Now().UTC()
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO peers(name, cert_serial, pubkey_fingerprint, authorized_key, created_at)
		 VALUES('beta', 9, 'SHA256:def', ?, ?)`,
		[]byte("ssh-ed25519 AAAA-beta"), now); err != nil {
		t.Fatalf("insert v3 peer: %v", err)
	}
	return raw
}

// TestMigratePreV4PreservesRowsDroppingDeadColumns starts from a schema_version=3
// db (no layout_version/address columns). migrate() must add those columns to reach
// the schema_version=5 shape and then drop the vestigial ones, leaving a clean peers
// table while preserving the seeded row.
func TestMigratePreV4PreservesRowsDroppingDeadColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v3.sqlite")
	raw := openV3DB(t, path)

	ctx := context.Background()
	if cols, err := (&DB{sql: raw}).tableHasColumns(ctx, "peers"); err != nil {
		t.Fatalf("tableHasColumns: %v", err)
	} else if cols["layout_version"] {
		t.Fatal("test precondition: v3 peers table must NOT have a layout_version column")
	}

	d := &DB{sql: raw}
	if err := d.migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	cols, err := d.tableHasColumns(ctx, "peers")
	if err != nil {
		t.Fatalf("tableHasColumns after migrate: %v", err)
	}
	for _, dead := range []string{"layout_version", "last_krl_version", "mode"} {
		if cols[dead] {
			t.Errorf("peers.%s should be dropped after migrate", dead)
		}
	}

	p, err := d.GetPeer(ctx, "beta")
	if err != nil {
		t.Fatalf("GetPeer after migrate: %v", err)
	}
	if p.Serial != 9 || p.Fingerprint != "SHA256:def" || string(p.AuthorizedKey) != "ssh-ed25519 AAAA-beta" {
		t.Errorf("peer row not preserved: %+v", p)
	}

	var ver string
	if err := raw.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='schema_version'`).Scan(&ver); err != nil {
		t.Fatalf("read schema_version: %v", err)
	}
	if ver != "7" {
		t.Errorf("schema_version = %q, want \"7\"", ver)
	}

	if err := raw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

const v4SchemaSQL = `
CREATE TABLE meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE peers (
  name TEXT PRIMARY KEY,
  cert_serial INTEGER NOT NULL,
  pubkey_fingerprint TEXT NOT NULL,
  authorized_key BLOB NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL,
  last_krl_version INTEGER NOT NULL DEFAULT 0,
  mode TEXT NOT NULL DEFAULT 'root',
  target_user TEXT NOT NULL DEFAULT '',
  layout_version INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE tokens (
  token TEXT PRIMARY KEY,
  peer_name TEXT NOT NULL,
  groups TEXT NOT NULL,
  tarball BLOB,
  consumed INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL,
  mode TEXT NOT NULL DEFAULT 'root',
  target_user TEXT NOT NULL DEFAULT ''
);
`

func openV4DB(t *testing.T, path string) *sql.DB {
	t.Helper()
	raw, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	raw.SetMaxOpenConns(1)
	ctx := context.Background()
	if _, err := raw.ExecContext(ctx, v4SchemaSQL); err != nil {
		t.Fatalf("apply v4 schema: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO meta(key, value) VALUES('schema_version', '4')`); err != nil {
		t.Fatalf("set schema_version=4: %v", err)
	}
	now := time.Now().UTC()
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO peers(name, cert_serial, pubkey_fingerprint, authorized_key, created_at)
		 VALUES('gamma', 11, 'SHA256:ghi', ?, ?)`,
		[]byte("ssh-ed25519 AAAA-gamma"), now); err != nil {
		t.Fatalf("insert v4 peer: %v", err)
	}
	return raw
}

func TestMigratePreV5AddsAddressColumnPreservingRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v4.sqlite")
	raw := openV4DB(t, path)

	ctx := context.Background()
	if cols, err := (&DB{sql: raw}).tableHasColumns(ctx, "peers"); err != nil {
		t.Fatalf("tableHasColumns: %v", err)
	} else if cols["address"] {
		t.Fatal("test precondition: v4 peers table must NOT have an address column")
	}

	d := &DB{sql: raw}
	if err := d.migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	cols, err := d.tableHasColumns(ctx, "peers")
	if err != nil {
		t.Fatalf("tableHasColumns after migrate: %v", err)
	}
	if !cols["address"] {
		t.Error("address column missing after migrate")
	}

	var notnull int
	var dflt any
	found := false
	rows, err := raw.QueryContext(ctx, "PRAGMA table_info(peers)")
	if err != nil {
		t.Fatalf("pragma: %v", err)
	}
	for rows.Next() {
		var cid, nn, pk int
		var name, ctype string
		var dv any
		if err := rows.Scan(&cid, &name, &ctype, &nn, &dv, &pk); err != nil {
			t.Fatalf("scan pragma: %v", err)
		}
		if name == "address" {
			found = true
			notnull = nn
			dflt = dv
		}
	}
	rows.Close()
	if !found {
		t.Fatal("address column not reported by PRAGMA")
	}
	if notnull != 1 {
		t.Errorf("address column should be NOT NULL (notnull=1), got notnull=%d", notnull)
	}
	if fmt.Sprintf("%v", dflt) != "''" {
		t.Errorf("address column should DEFAULT '' , got %v", dflt)
	}

	p, err := d.GetPeer(ctx, "gamma")
	if err != nil {
		t.Fatalf("GetPeer after migrate: %v", err)
	}
	if p.Serial != 11 || p.Fingerprint != "SHA256:ghi" || string(p.AuthorizedKey) != "ssh-ed25519 AAAA-gamma" {
		t.Errorf("peer row not preserved: %+v", p)
	}
	if p.Address != "" {
		t.Errorf("Address = %q, want empty for a migrated row", p.Address)
	}

	var ver string
	if err := raw.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='schema_version'`).Scan(&ver); err != nil {
		t.Fatalf("read schema_version: %v", err)
	}
	if ver != "7" {
		t.Errorf("schema_version = %q, want \"7\"", ver)
	}

	if err := raw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestAddTarballColumnIdempotent(t *testing.T) {
	d := newTestDB(t)
	ctx := t.Context()
	if err := d.InsertToken(ctx, "tok", "p", "g", "", nil); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}
	if err := d.addTarballColumn(ctx); err != nil {
		t.Fatalf("addTarballColumn second run: %v", err)
	}
	if err := d.addTarballColumn(ctx); err != nil {
		t.Fatalf("addTarballColumn third run: %v", err)
	}
	peer, groups, _, consumed, err := d.LookupToken(ctx, "tok")
	if err != nil {
		t.Fatalf("LookupToken: %v", err)
	}
	if peer != "p" || groups != "g" || consumed {
		t.Errorf("row not preserved after repeated addTarballColumn: peer=%q groups=%q consumed=%v", peer, groups, consumed)
	}
}

// v5SchemaSQL is the full historical schema_version=5 shape: the base tables plus
// every column added by the incremental add* migrations, including the now-vestigial
// mode / layout_version / last_krl_version columns and the dead krl_version table.
const v5SchemaSQL = `
CREATE TABLE meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE peers (
  name TEXT PRIMARY KEY,
  cert_serial INTEGER NOT NULL,
  pubkey_fingerprint TEXT NOT NULL,
  authorized_key BLOB NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL,
  last_krl_version INTEGER NOT NULL DEFAULT 0,
  mode TEXT NOT NULL DEFAULT 'root',
  target_user TEXT NOT NULL DEFAULT '',
  layout_version INTEGER NOT NULL DEFAULT 1,
  address TEXT NOT NULL DEFAULT ''
);
CREATE TABLE groups (
  name TEXT PRIMARY KEY
);
CREATE TABLE peer_groups (
  peer_name TEXT NOT NULL REFERENCES peers(name),
  group_name TEXT NOT NULL REFERENCES groups(name),
  PRIMARY KEY (peer_name, group_name)
);
CREATE TABLE peer_allowed_groups (
  peer_name TEXT NOT NULL REFERENCES peers(name),
  group_name TEXT NOT NULL REFERENCES groups(name),
  PRIMARY KEY (peer_name, group_name)
);
CREATE TABLE tokens (
  token TEXT PRIMARY KEY,
  peer_name TEXT NOT NULL,
  groups TEXT NOT NULL,
  tarball BLOB,
  consumed INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL,
  mode TEXT NOT NULL DEFAULT 'root',
  target_user TEXT NOT NULL DEFAULT ''
);
CREATE TABLE ca (
  version INTEGER PRIMARY KEY,
  active INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL
);
CREATE TABLE krl_version (
  version INTEGER PRIMARY KEY,
  generated_at TIMESTAMP NOT NULL
);
`

func openV5DB(t *testing.T, path string) *sql.DB {
	t.Helper()
	raw, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	raw.SetMaxOpenConns(1)
	ctx := context.Background()
	if _, err := raw.ExecContext(ctx, v5SchemaSQL); err != nil {
		t.Fatalf("apply v5 schema: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO meta(key, value) VALUES('schema_version', '5')`); err != nil {
		t.Fatalf("set schema_version=5: %v", err)
	}
	now := time.Now().UTC()
	// Two peers: one user-mode with a target_user + address, one "root"-mode with neither.
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO peers(name, cert_serial, pubkey_fingerprint, authorized_key, revoked, created_at, last_krl_version, mode, target_user, layout_version, address)
		 VALUES('vmU', 7, 'SHA256:abc', ?, 0, ?, 3, 'user', 'alice', 2, '10.0.0.5')`,
		[]byte("ssh-ed25519 AAAA-vmU"), now); err != nil {
		t.Fatalf("insert v5 peer vmU: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO peers(name, cert_serial, pubkey_fingerprint, authorized_key, revoked, created_at, last_krl_version, mode, target_user, layout_version, address)
		 VALUES('vmR', 9, 'SHA256:def', ?, 1, ?, 0, 'root', '', 1, '')`,
		[]byte("ssh-ed25519 AAAA-vmR"), now); err != nil {
		t.Fatalf("insert v5 peer vmR: %v", err)
	}
	// Group membership rows that reference peers(name)/groups(name) — these must
	// still resolve (FK-clean) after the rebuild.
	for _, g := range []string{"infra", "db"} {
		if _, err := raw.ExecContext(ctx, `INSERT INTO groups(name) VALUES(?)`, g); err != nil {
			t.Fatalf("insert group %s: %v", g, err)
		}
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO peer_groups(peer_name, group_name) VALUES('vmU','infra'),('vmU','db')`); err != nil {
		t.Fatalf("insert peer_groups: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO peer_allowed_groups(peer_name, group_name) VALUES('vmU','infra')`); err != nil {
		t.Fatalf("insert peer_allowed_groups: %v", err)
	}
	// Two tokens: one unconsumed user-mode token carrying a tarball, one consumed.
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO tokens(token, peer_name, groups, tarball, consumed, created_at, mode, target_user)
		 VALUES('tok-open', 'vmU', 'infra,db', ?, 0, ?, 'user', 'alice')`,
		[]byte("tarball-bytes"), now); err != nil {
		t.Fatalf("insert v5 token tok-open: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO tokens(token, peer_name, groups, tarball, consumed, created_at, mode, target_user)
		 VALUES('tok-done', 'vmR', 'infra', NULL, 1, ?, 'root', '')`,
		now); err != nil {
		t.Fatalf("insert v5 token tok-done: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO krl_version(version, generated_at) VALUES(4, ?)`, now); err != nil {
		t.Fatalf("insert krl_version row: %v", err)
	}
	return raw
}

// TestMigrateV5DropsDeadColumnsPreservingRows is the headline T09 test: it builds a
// schema_version=5 db with the vestigial mode/layout_version/last_krl_version columns
// and a krl_version table populated, runs migrate, and asserts those are gone, all
// rows are preserved, schema_version is bumped to 6, the migration is idempotent
// (3 runs), and foreign keys still check out.
func TestMigrateV5DropsDeadColumnsPreservingRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v5.sqlite")
	raw := openV5DB(t, path)
	d := &DB{sql: raw}
	ctx := context.Background()

	// Run migrate 3x to prove idempotency: the dropDeadColumns guard must no-op
	// once the columns are gone, and rows must survive every run.
	for i := 0; i < 3; i++ {
		if err := d.migrate(ctx); err != nil {
			t.Fatalf("migrate run %d: %v", i+1, err)
		}
	}

	// Dead peer columns gone.
	peerCols, err := d.tableHasColumns(ctx, "peers")
	if err != nil {
		t.Fatalf("tableHasColumns(peers): %v", err)
	}
	for _, dead := range []string{"mode", "layout_version", "last_krl_version"} {
		if peerCols[dead] {
			t.Errorf("peers.%s still present after migrate", dead)
		}
	}
	for _, kept := range []string{"name", "cert_serial", "pubkey_fingerprint", "authorized_key", "revoked", "created_at", "target_user", "address"} {
		if !peerCols[kept] {
			t.Errorf("peers.%s missing after migrate", kept)
		}
	}

	// tokens.mode gone, kept columns present.
	tokCols, err := d.tableHasColumns(ctx, "tokens")
	if err != nil {
		t.Fatalf("tableHasColumns(tokens): %v", err)
	}
	if tokCols["mode"] {
		t.Error("tokens.mode still present after migrate")
	}
	for _, kept := range []string{"token", "peer_name", "groups", "tarball", "consumed", "created_at", "target_user"} {
		if !tokCols[kept] {
			t.Errorf("tokens.%s missing after migrate", kept)
		}
	}

	// krl_version table dropped.
	var n int
	if err := raw.QueryRowContext(ctx,
		`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='krl_version'`).Scan(&n); err != nil {
		t.Fatalf("query sqlite_master: %v", err)
	}
	if n != 0 {
		t.Error("krl_version table still present after migrate")
	}

	// Peer rows preserved with kept-column values intact.
	pU, err := d.GetPeer(ctx, "vmU")
	if err != nil {
		t.Fatalf("GetPeer vmU: %v", err)
	}
	if pU.Serial != 7 || pU.Fingerprint != "SHA256:abc" || string(pU.AuthorizedKey) != "ssh-ed25519 AAAA-vmU" ||
		pU.Revoked || pU.TargetUser != "alice" || pU.Address != "10.0.0.5" {
		t.Errorf("vmU not preserved: %+v", pU)
	}
	pR, err := d.GetPeer(ctx, "vmR")
	if err != nil {
		t.Fatalf("GetPeer vmR: %v", err)
	}
	if pR.Serial != 9 || pR.Fingerprint != "SHA256:def" || string(pR.AuthorizedKey) != "ssh-ed25519 AAAA-vmR" ||
		!pR.Revoked || pR.TargetUser != "" || pR.Address != "" {
		t.Errorf("vmR not preserved: %+v", pR)
	}

	// Token rows preserved: open token keeps groups/target_user/tarball/unconsumed.
	peer, groups, tu, consumed, err := d.LookupToken(ctx, "tok-open")
	if err != nil {
		t.Fatalf("LookupToken tok-open: %v", err)
	}
	if peer != "vmU" || groups != "infra,db" || tu != "alice" || consumed {
		t.Errorf("tok-open not preserved: peer=%q groups=%q tu=%q consumed=%v", peer, groups, tu, consumed)
	}
	var tarball []byte
	if err := raw.QueryRowContext(ctx, `SELECT tarball FROM tokens WHERE token='tok-open'`).Scan(&tarball); err != nil {
		t.Fatalf("select tok-open tarball: %v", err)
	}
	if string(tarball) != "tarball-bytes" {
		t.Errorf("tok-open tarball = %q, want tarball-bytes", tarball)
	}
	peer, groups, tu, consumed, err = d.LookupToken(ctx, "tok-done")
	if err != nil {
		t.Fatalf("LookupToken tok-done: %v", err)
	}
	if peer != "vmR" || groups != "infra" || tu != "" || !consumed {
		t.Errorf("tok-done not preserved: peer=%q groups=%q tu=%q consumed=%v", peer, groups, tu, consumed)
	}

	// Group membership rows still resolve.
	gs, err := d.GetPeerGroups(ctx, "vmU")
	if err != nil {
		t.Fatalf("GetPeerGroups vmU: %v", err)
	}
	if len(gs) != 2 {
		t.Errorf("vmU groups = %v, want 2", gs)
	}
	ags, err := d.GetPeerAllowedGroups(ctx, "vmU")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups vmU: %v", err)
	}
	if len(ags) != 1 || ags[0] != "infra" {
		t.Errorf("vmU allowed groups = %v, want [infra]", ags)
	}

	// schema_version bumped to 6.
	var ver string
	if err := raw.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='schema_version'`).Scan(&ver); err != nil {
		t.Fatalf("read schema_version: %v", err)
	}
	if ver != "7" {
		t.Errorf("schema_version = %q, want \"7\"", ver)
	}

	// Foreign keys clean.
	fkRows, err := raw.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatalf("foreign_key_check: %v", err)
	}
	defer fkRows.Close()
	if fkRows.Next() {
		t.Error("foreign_key_check reported a violation after migrate")
	}

	if err := raw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// v6SchemaSQL is the clean schema_version=6 shape left by dropDeadColumns: no
// vestigial columns, no krl_version table, and none of the client-peer columns
// (inbound/pull_token/cert) added at schema_version=7.
const v6SchemaSQL = `
CREATE TABLE meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE peers (
  name TEXT PRIMARY KEY,
  cert_serial INTEGER NOT NULL,
  pubkey_fingerprint TEXT NOT NULL,
  authorized_key BLOB NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL,
  target_user TEXT NOT NULL DEFAULT '',
  address TEXT NOT NULL DEFAULT ''
);
CREATE TABLE groups (
  name TEXT PRIMARY KEY
);
CREATE TABLE peer_groups (
  peer_name TEXT NOT NULL REFERENCES peers(name),
  group_name TEXT NOT NULL REFERENCES groups(name),
  PRIMARY KEY (peer_name, group_name)
);
CREATE TABLE peer_allowed_groups (
  peer_name TEXT NOT NULL REFERENCES peers(name),
  group_name TEXT NOT NULL REFERENCES groups(name),
  PRIMARY KEY (peer_name, group_name)
);
CREATE TABLE tokens (
  token TEXT PRIMARY KEY,
  peer_name TEXT NOT NULL,
  groups TEXT NOT NULL,
  tarball BLOB,
  consumed INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL,
  target_user TEXT NOT NULL DEFAULT ''
);
CREATE TABLE ca (
  version INTEGER PRIMARY KEY,
  active INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL
);
`

func openV6DB(t *testing.T, path string) *sql.DB {
	t.Helper()
	raw, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	raw.SetMaxOpenConns(1)
	ctx := context.Background()
	if _, err := raw.ExecContext(ctx, v6SchemaSQL); err != nil {
		t.Fatalf("apply v6 schema: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO meta(key, value) VALUES('schema_version', '6')`); err != nil {
		t.Fatalf("set schema_version=6: %v", err)
	}
	now := time.Now().UTC()
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO peers(name, cert_serial, pubkey_fingerprint, authorized_key, revoked, created_at, target_user, address)
		 VALUES('delta', 13, 'SHA256:jkl', ?, 0, ?, 'alice', '10.0.0.7')`,
		[]byte("ssh-ed25519 AAAA-delta"), now); err != nil {
		t.Fatalf("insert v6 peer: %v", err)
	}
	return raw
}

// TestMigrateV6AddsClientPeerColumns starts from a clean schema_version=6 db and
// asserts migrate adds the inbound/pull_token/cert columns with the right defaults,
// preserves the seeded row (reading back inbound=true, empty pull_token, nil cert),
// bumps schema_version to 7, and is idempotent.
func TestMigrateV6AddsClientPeerColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v6.sqlite")
	raw := openV6DB(t, path)

	ctx := context.Background()
	if cols, err := (&DB{sql: raw}).tableHasColumns(ctx, "peers"); err != nil {
		t.Fatalf("tableHasColumns: %v", err)
	} else if cols["inbound"] || cols["pull_token"] || cols["cert"] {
		t.Fatal("test precondition: v6 peers table must NOT have inbound/pull_token/cert columns")
	}

	d := &DB{sql: raw}
	for i := 0; i < 2; i++ {
		if err := d.migrate(ctx); err != nil {
			t.Fatalf("migrate run %d: %v", i+1, err)
		}
	}

	type colInfo struct {
		notnull int
		dflt    any
	}
	got := map[string]colInfo{}
	rows, err := raw.QueryContext(ctx, "PRAGMA table_info(peers)")
	if err != nil {
		t.Fatalf("pragma: %v", err)
	}
	for rows.Next() {
		var cid, nn, pk int
		var name, ctype string
		var dv any
		if err := rows.Scan(&cid, &name, &ctype, &nn, &dv, &pk); err != nil {
			t.Fatalf("scan pragma: %v", err)
		}
		got[name] = colInfo{notnull: nn, dflt: dv}
	}
	rows.Close()
	want := map[string]struct {
		notnull int
		dflt    string
	}{
		"inbound":    {notnull: 1, dflt: "1"},
		"pull_token": {notnull: 1, dflt: "''"},
		"cert":       {notnull: 0, dflt: "<nil>"},
	}
	for col, w := range want {
		ci, ok := got[col]
		if !ok {
			t.Errorf("peers.%s missing after migrate", col)
			continue
		}
		if ci.notnull != w.notnull {
			t.Errorf("peers.%s notnull = %d, want %d", col, ci.notnull, w.notnull)
		}
		if fmt.Sprintf("%v", ci.dflt) != w.dflt {
			t.Errorf("peers.%s default = %v, want %s", col, ci.dflt, w.dflt)
		}
	}

	p, err := d.GetPeer(ctx, "delta")
	if err != nil {
		t.Fatalf("GetPeer after migrate: %v", err)
	}
	if p.Serial != 13 || p.Fingerprint != "SHA256:jkl" || string(p.AuthorizedKey) != "ssh-ed25519 AAAA-delta" ||
		p.Revoked || p.TargetUser != "alice" || p.Address != "10.0.0.7" {
		t.Errorf("peer row not preserved: %+v", p)
	}
	if !p.Inbound {
		t.Error("migrated peer should default to Inbound=true")
	}
	if p.PullToken != "" {
		t.Errorf("PullToken = %q, want empty for a migrated row", p.PullToken)
	}
	if p.Cert != nil {
		t.Errorf("Cert = %v, want nil for a migrated row", p.Cert)
	}

	var ver string
	if err := raw.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='schema_version'`).Scan(&ver); err != nil {
		t.Fatalf("read schema_version: %v", err)
	}
	if ver != "7" {
		t.Errorf("schema_version = %q, want \"7\"", ver)
	}

	if err := raw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}
