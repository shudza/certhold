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

	peer, groups, mode, tu, consumed, err := d.LookupToken(ctx, "tok-v2")
	if err != nil {
		t.Fatalf("LookupToken after migrate: %v", err)
	}
	if peer != "alpha" || groups != "infra,db" || mode != "root" || tu != "" || consumed {
		t.Errorf("token row not preserved: peer=%q groups=%q mode=%q tu=%q consumed=%v", peer, groups, mode, tu, consumed)
	}

	var ver string
	if err := raw.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='schema_version'`).Scan(&ver); err != nil {
		t.Fatalf("read schema_version: %v", err)
	}
	if ver != "4" {
		t.Errorf("schema_version = %q, want \"4\"", ver)
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

func TestMigratePreV4AddsLayoutVersionColumnPreservingRows(t *testing.T) {
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
	if !cols["layout_version"] {
		t.Error("layout_version column missing after migrate")
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
		if name == "layout_version" {
			found = true
			notnull = nn
			dflt = dv
		}
	}
	rows.Close()
	if !found {
		t.Fatal("layout_version column not reported by PRAGMA")
	}
	if notnull != 1 {
		t.Errorf("layout_version column should be NOT NULL (notnull=1), got notnull=%d", notnull)
	}
	if fmt.Sprintf("%v", dflt) != "1" {
		t.Errorf("layout_version column should DEFAULT 1, got %v", dflt)
	}

	p, err := d.GetPeer(ctx, "beta")
	if err != nil {
		t.Fatalf("GetPeer after migrate: %v", err)
	}
	if p.Serial != 9 || p.Fingerprint != "SHA256:def" || string(p.AuthorizedKey) != "ssh-ed25519 AAAA-beta" {
		t.Errorf("peer row not preserved: %+v", p)
	}
	if p.LayoutVersion != 1 {
		t.Errorf("LayoutVersion = %d, want 1", p.LayoutVersion)
	}

	var ver string
	if err := raw.QueryRowContext(ctx, `SELECT value FROM meta WHERE key='schema_version'`).Scan(&ver); err != nil {
		t.Fatalf("read schema_version: %v", err)
	}
	if ver != "4" {
		t.Errorf("schema_version = %q, want \"4\"", ver)
	}

	if err := raw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestAddTarballColumnIdempotent(t *testing.T) {
	d := newTestDB(t)
	ctx := t.Context()
	if err := d.InsertToken(ctx, "tok", "p", "g"); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}
	if err := d.addTarballColumn(ctx); err != nil {
		t.Fatalf("addTarballColumn second run: %v", err)
	}
	if err := d.addTarballColumn(ctx); err != nil {
		t.Fatalf("addTarballColumn third run: %v", err)
	}
	peer, groups, _, _, consumed, err := d.LookupToken(ctx, "tok")
	if err != nil {
		t.Fatalf("LookupToken: %v", err)
	}
	if peer != "p" || groups != "g" || consumed {
		t.Errorf("row not preserved after repeated addTarballColumn: peer=%q groups=%q consumed=%v", peer, groups, consumed)
	}
}
