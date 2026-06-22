package ops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shudza/certhold/internal/ca"
)

func nextCADirExists(t *testing.T, dataDir string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(dataDir, "ca.next"))
	if err == nil {
		return true
	}
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	t.Fatalf("stat ca.next: %v", err)
	return false
}

// TestRekeyAbortBeforeRotationCleansStagingDir: an abort that happens before any
// peer is rotated on disk (the corrupt peer's ParseAuthorizedKey fails before
// any push/self-write succeeds) must remove ca.next, so a second rekey on the
// same datadir gets past the start guard.
func TestRekeyAbortBeforeRotationCleansStagingDir(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "mgr")
	ctx := context.Background()
	// Insert a corrupt peer that sorts before "mgr" so it is processed first in
	// the others loop; its parse failure aborts before any rotation.
	if err := d.InsertPeer(ctx, "aa-corrupt", 1, "fp-garbage", []byte("not a valid authorized key"), "root", true, ""); err != nil {
		t.Fatalf("InsertPeer corrupt: %v", err)
	}

	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	err := Rekey(ctx, deps, RekeyOptions{Hostname: "mgr"})
	if err == nil {
		t.Fatal("expected abort error")
	}
	if !strings.HasPrefix(err.Error(), "parse pubkey for aa-corrupt: ") {
		t.Fatalf("err = %q, want parse pubkey cause", err)
	}

	if nextCADirExists(t, dataDir) {
		t.Fatal("ca.next must be removed after an abort with no on-disk rotation")
	}

	// No recovery warning should be emitted when nothing was rotated.
	for _, e := range events {
		if e.Type == EventWarn && strings.Contains(e.Msg, "staged at") {
			t.Errorf("unexpected recovery warning when nothing rotated: %q", e.Msg)
		}
	}

	// Delete the corrupt peer so the retry can complete, and confirm the start
	// guard does NOT block (the real assertion is that we get past "already
	// exists").
	if err := d.DeletePeer(ctx, "aa-corrupt"); err != nil {
		t.Fatalf("DeletePeer: %v", err)
	}
	dialer2 := &fakeDialer{}
	var events2 []Event
	deps2 := collectingDeps(dataDir, d, dialer2, &events2)
	if err := Rekey(ctx, deps2, RekeyOptions{Hostname: "mgr"}); err != nil {
		t.Fatalf("second rekey must proceed past the start guard, got %v", err)
	}
}

// TestRekeyAbortAfterRotationPreservesStagingDir: once at least one peer has
// been rotated on disk to the new CA, an abort must PRESERVE ca.next and emit a
// recovery warning. A subsequent rekey then correctly hits the start guard.
func TestRekeyAbortAfterRotationPreservesStagingDir(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "alpha", "mgr")
	ctx := context.Background()
	// "alpha" is push-reachable and pushed successfully (rotatedAny=true), then
	// a corrupt peer sorting after alpha aborts the rekey.
	if err := d.InsertPeer(ctx, "zz-corrupt", 1, "fp-garbage", []byte("not a valid authorized key"), "root", true, ""); err != nil {
		t.Fatalf("InsertPeer corrupt: %v", err)
	}

	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	err := Rekey(ctx, deps, RekeyOptions{Hostname: "mgr"})
	if err == nil {
		t.Fatal("expected abort error")
	}
	if !strings.HasPrefix(err.Error(), "parse pubkey for zz-corrupt: ") {
		t.Fatalf("err = %q, want parse pubkey cause", err)
	}

	// alpha must have been pushed before the abort.
	pushedAlpha := false
	for _, c := range dialer.snapshot() {
		if c.host == "alpha" {
			pushedAlpha = true
		}
	}
	if !pushedAlpha {
		t.Fatal("alpha should have been pushed before the abort")
	}

	if !nextCADirExists(t, dataDir) {
		t.Fatal("ca.next must be preserved after an abort with at least one on-disk rotation")
	}

	sawRecovery := false
	for _, e := range events {
		if e.Type == EventWarn && strings.Contains(e.Msg, filepath.Join(dataDir, "ca.next")) && strings.Contains(e.Msg, "Manual recovery is required") {
			sawRecovery = true
		}
	}
	if !sawRecovery {
		t.Fatalf("expected recovery warning naming ca.next; events=%+v", events)
	}

	// A retry on the same datadir must now hit the start guard.
	dialer2 := &fakeDialer{}
	var events2 []Event
	deps2 := collectingDeps(dataDir, d, dialer2, &events2)
	err = Rekey(ctx, deps2, RekeyOptions{Hostname: "mgr"})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("retry should hit the start guard, got %v", err)
	}
}

// TestRekeyGenerateFailureCleansPartialStagingDir: if CA generation fails AFTER
// creating the ca.next dir (its MkdirAll runs before any error), the cleanup
// defer must still remove the partial ca.next. Otherwise the leaked dir would
// trip the start guard and block ALL future rekeys — the exact regression this
// guards. We simulate the generate-time failure by overriding generateCA so it
// creates the dir and then returns an error, mirroring GenerateWithPassphrase's
// own MkdirAll-then-fail ordering.
func TestRekeyGenerateFailureCleansPartialStagingDir(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "alpha", "mgr")
	ctx := context.Background()

	orig := generateCA
	t.Cleanup(func() { generateCA = orig })
	generateCA = func(dir string, pass []byte) (*ca.CA, error) {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatalf("simulated generate MkdirAll: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "ca"), []byte("partial"), 0600); err != nil {
			t.Fatalf("simulated generate partial write: %v", err)
		}
		return nil, errors.New("simulated generate failure")
	}

	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	err := Rekey(ctx, deps, RekeyOptions{Hostname: "mgr"})
	if err == nil || !strings.Contains(err.Error(), "generate new ca") {
		t.Fatalf("err = %v, want a generate-new-ca failure", err)
	}

	if nextCADirExists(t, dataDir) {
		t.Fatal("partial ca.next must be removed after a generate-phase failure")
	}
	for _, e := range events {
		if e.Type == EventWarn && strings.Contains(e.Msg, "staged at") {
			t.Errorf("no recovery warning expected when nothing was rotated: %q", e.Msg)
		}
	}

	// Restore real generation and confirm a retry on the same datadir is NOT
	// blocked by the start guard (the leaked-dir regression).
	generateCA = orig
	dialer2 := &fakeDialer{}
	var events2 []Event
	deps2 := collectingDeps(dataDir, d, dialer2, &events2)
	if err := Rekey(ctx, deps2, RekeyOptions{Hostname: "mgr"}); err != nil {
		t.Fatalf("retry must proceed past the start guard, got %v", err)
	}
}

// TestRekeyHappyPathRemovesStagingDir: the committed swap renames ca.next away;
// the not-committed defer must be a no-op (no double-remove/panic) and ca.next
// must not be present afterward.
func TestRekeyHappyPathRemovesStagingDir(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "alpha", "beta", "mgr")
	ctx := context.Background()
	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	if err := Rekey(ctx, deps, RekeyOptions{Hostname: "mgr"}); err != nil {
		t.Fatalf("Rekey: %v", err)
	}

	if nextCADirExists(t, dataDir) {
		t.Fatal("ca.next must not remain after a committed rekey")
	}
	// Sanity: the live CA exists (swap landed the new CA at ca).
	if _, err := os.Stat(filepath.Join(dataDir, "ca", "ca.pub")); err != nil {
		t.Fatalf("live ca.pub missing after rekey: %v", err)
	}
	for _, e := range events {
		if e.Type == EventWarn {
			t.Errorf("unexpected warn on happy path: %+v", e)
		}
	}
}
