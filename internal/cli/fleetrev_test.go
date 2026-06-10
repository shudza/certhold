package cli

import (
	"context"
	"testing"

	"github.com/shudza/certhold/internal/db"
)

func fleetRevOf(t *testing.T, dbPath string) int64 {
	t.Helper()
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	rev, err := d.FleetRev(context.Background())
	if err != nil {
		t.Fatalf("FleetRev: %v", err)
	}
	return rev
}

// TestFleetRevBumpsExactlyOncePerMutatingCommand drives every mutating command
// once against its own fixture and asserts fleet_rev moves by exactly 1.
func TestFleetRevBumpsExactlyOncePerMutatingCommand(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T) (dbPath string, run func())
	}{
		{
			name: "update",
			setup: func(t *testing.T) (string, func()) {
				dataDir, dbPath, _ := setupUpdateEnv(t, "peer1", []string{"oldA"}, false)
				preCreateGroups(t, dbPath, "newA")
				withMockPusher(t)
				return dbPath, func() {
					if _, stderr, err := runUpdate(t, dataDir, dbPath, "peer1", "--groups", "newA"); err != nil {
						t.Fatalf("update: err=%v stderr=%s", err, stderr)
					}
				}
			},
		},
		{
			name: "rekey",
			setup: func(t *testing.T) (string, func()) {
				dataDir, dbPath, hostname, _, cleanup := setupRekeyEnv(t, nil)
				t.Cleanup(cleanup)
				return dbPath, func() {
					if _, stderr, err := runRekeyCmd(t, dataDir, dbPath, hostname); err != nil {
						t.Fatalf("rekey: err=%v stderr=%s", err, stderr)
					}
				}
			},
		},
		{
			name: "revoke",
			setup: func(t *testing.T) (string, func()) {
				dataDir, dbPath, hostname, _, cleanup := setupRekeyEnv(t, nil)
				t.Cleanup(cleanup)
				return dbPath, func() {
					if _, stderr, err := runRevokeCmd(t, dataDir, dbPath, "alpha", "--hostname", hostname); err != nil {
						t.Fatalf("revoke: err=%v stderr=%s", err, stderr)
					}
				}
			},
		},
		{
			name: "group create",
			setup: func(t *testing.T) (string, func()) {
				dataDir, dbPath := freshGroupDB(t)
				return dbPath, func() {
					if out, err := runGroupCmd(t, dataDir, dbPath, "create", "infra"); err != nil {
						t.Fatalf("create: err=%v out=%s", err, out)
					}
				}
			},
		},
		{
			name: "group delete",
			setup: func(t *testing.T) (string, func()) {
				dataDir, dbPath := freshGroupDB(t)
				preCreateGroups(t, dbPath, "infra")
				return dbPath, func() {
					if out, err := runGroupCmd(t, dataDir, dbPath, "delete", "infra"); err != nil {
						t.Fatalf("delete: err=%v out=%s", err, out)
					}
				}
			},
		},
		{
			name: "group rename",
			setup: func(t *testing.T) (string, func()) {
				dataDir, dbPath := freshGroupDB(t)
				preCreateGroups(t, dbPath, "web")
				return dbPath, func() {
					if out, err := runGroupCmd(t, dataDir, dbPath, "rename", "web", "public"); err != nil {
						t.Fatalf("rename: err=%v out=%s", err, out)
					}
				}
			},
		},
		{
			name: "group allow",
			setup: func(t *testing.T) (string, func()) {
				dataDir, dbPath := seedGroupDB(t, []string{"a"})
				preCreateGroups(t, dbPath, "c")
				installFakePusher(t, dataDir, caLineFor(t, dataDir, "manager", "a"))
				return dbPath, func() {
					if out, err := runGroupCmd(t, dataDir, dbPath, "allow", "c", "--on", "peer1"); err != nil {
						t.Fatalf("allow: err=%v out=%s", err, out)
					}
				}
			},
		},
		{
			name: "group disallow",
			setup: func(t *testing.T) (string, func()) {
				dataDir, dbPath := seedGroupDB(t, []string{"a", "b"})
				installFakePusher(t, dataDir, caLineFor(t, dataDir, "manager", "a", "b"))
				return dbPath, func() {
					if out, err := runGroupCmd(t, dataDir, dbPath, "disallow", "a", "--on", "peer1"); err != nil {
						t.Fatalf("disallow: err=%v out=%s", err, out)
					}
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dbPath, run := tc.setup(t)
			before := fleetRevOf(t, dbPath)
			run()
			after := fleetRevOf(t, dbPath)
			if after != before+1 {
				t.Errorf("fleet_rev = %d after %s, want %d (exactly one bump from %d)", after, tc.name, before+1, before)
			}
		})
	}
}

// fleet_rev must NOT move when a mutating command rejects its input.
func TestFleetRevUnchangedOnRejectedMutation(t *testing.T) {
	dataDir, dbPath := freshGroupDB(t)
	preCreateGroups(t, dbPath, "infra")
	before := fleetRevOf(t, dbPath)
	if _, err := runGroupCmd(t, dataDir, dbPath, "create", "infra"); err == nil {
		t.Fatal("expected duplicate create to fail")
	}
	if _, err := runGroupCmd(t, dataDir, dbPath, "delete", "nope"); err == nil {
		t.Fatal("expected delete of missing group to fail")
	}
	if after := fleetRevOf(t, dbPath); after != before {
		t.Errorf("fleet_rev = %d after rejected mutations, want %d", after, before)
	}
}
