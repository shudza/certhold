package ops

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/sshpush"
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

// rekeyAbortDialer delegates to a fakeDialer but fails exactly one push
// operation ("dial", "read", "write-authorized-keys", "write-cert", "splice",
// "verify") on one host, to simulate a peer push dying at a chosen point of the
// rekey sequence.
type rekeyAbortDialer struct {
	inner    *fakeDialer
	failHost string
	failOp   string
	failErr  error
}

func (d *rekeyAbortDialer) dial(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
	if host == d.failHost && d.failOp == "dial" {
		return nil, d.failErr
	}
	p, err := d.inner.dial(ctx, host, opts)
	if err != nil {
		return nil, err
	}
	if host != d.failHost {
		return p, nil
	}
	return &rekeyAbortPusher{Pusher: p, d: d}, nil
}

type rekeyAbortPusher struct {
	sshpush.Pusher
	d *rekeyAbortDialer
}

func (p *rekeyAbortPusher) ReadFile(ctx context.Context, remotePath string) ([]byte, error) {
	if p.d.failOp == "read" {
		return nil, p.d.failErr
	}
	return p.Pusher.ReadFile(ctx, remotePath)
}

func (p *rekeyAbortPusher) WriteFileAtomic(ctx context.Context, remotePath string, content []byte, mode fs.FileMode) error {
	isAK := strings.HasSuffix(remotePath, "authorized_keys")
	if (p.d.failOp == "write-authorized-keys" && isAK) || (p.d.failOp == "write-cert" && !isAK) {
		return p.d.failErr
	}
	return p.Pusher.WriteFileAtomic(ctx, remotePath, content, mode)
}

func (p *rekeyAbortPusher) SpliceConfigBlock(ctx context.Context, configPath, instanceKey, block string) error {
	if p.d.failOp == "splice" {
		return p.d.failErr
	}
	return p.Pusher.SpliceConfigBlock(ctx, configPath, instanceKey, block)
}

func (p *rekeyAbortPusher) VerifyHealth(ctx context.Context) error {
	if p.d.failOp == "verify" {
		return p.d.failErr
	}
	return p.Pusher.VerifyHealth(ctx)
}

func rekeyAbortDeps(dataDir string, d *db.DB, dial DialFn, events *[]Event) Deps {
	return Deps{
		DB:      d,
		DataDir: dataDir,
		Dial:    dial,
		OnEvent: func(e Event) { *events = append(*events, e) },
	}
}

// rekeyAbortInsertCorruptPeer inserts a peer whose stored pubkey does not
// parse, so the rekey loop aborts when it reaches that peer.
func rekeyAbortInsertCorruptPeer(t *testing.T, d *db.DB, name string) {
	t.Helper()
	if err := d.InsertPeer(context.Background(), name, 1, "fp-garbage", []byte("not a valid authorized key"), "root", true, ""); err != nil {
		t.Fatalf("InsertPeer %s: %v", name, err)
	}
}

// rekeyAbortInsertClientPeer inserts a client-style (no-inbound) peer holding
// the given pre-rekey cert and serial, so its rekey update is DB-only via the
// skip-notice branch.
func rekeyAbortInsertClientPeer(t *testing.T, d *db.DB, name string, cert []byte, serial uint64) {
	t.Helper()
	ctx := context.Background()
	_, pubAuth, sshPub, err := ca.GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey %s: %v", name, err)
	}
	if err := d.InsertPeer(ctx, name, 100, ssh.FingerprintSHA256(sshPub), pubAuth, "root", false, "tok-"+name); err != nil {
		t.Fatalf("InsertPeer %s: %v", name, err)
	}
	if err := d.SetPeerCert(ctx, name, cert, serial); err != nil {
		t.Fatalf("SetPeerCert %s: %v", name, err)
	}
}

// TestRekeyAbortAfterPartialPushPreservesStagingDir: a push that gets as far as
// issuing the authorized_keys write may have swapped the peer's trust root to
// the new CA even when a later step (or the write itself, ambiguously) fails.
// A subsequent abort must PRESERVE ca.next — it may be the only CA that peer
// now trusts — and must NOT roll back skip-notice DB-only certs, which can
// still become valid when the operator finishes the rotation.
func TestRekeyAbortAfterPartialPushPreservesStagingDir(t *testing.T) {
	for _, failOp := range []string{"write-authorized-keys", "write-cert", "splice", "verify"} {
		t.Run(failOp, func(t *testing.T) {
			dataDir, d := setupOpsEnv(t, "alpha", "mgr")
			ctx := context.Background()
			priorCert := []byte("prior-client-cert")
			rekeyAbortInsertClientPeer(t, d, "aa-client", priorCert, 7)
			rekeyAbortInsertCorruptPeer(t, d, "zz-corrupt")

			dialer := &rekeyAbortDialer{
				inner:    &fakeDialer{},
				failHost: "alpha",
				failOp:   failOp,
				failErr:  errors.New("simulated " + failOp + " failure"),
			}
			var events []Event
			deps := rekeyAbortDeps(dataDir, d, dialer.dial, &events)

			err := Rekey(ctx, deps, RekeyOptions{Hostname: "mgr"})
			if err == nil || !strings.HasPrefix(err.Error(), "parse pubkey for zz-corrupt: ") {
				t.Fatalf("err = %v, want parse-pubkey abort cause", err)
			}

			sawFailed := false
			for _, e := range events {
				if e.Type == EventPeerFailed && e.Peer == "alpha" {
					sawFailed = true
				}
			}
			if !sawFailed {
				t.Fatal("alpha should have been reported as a failed push before the abort")
			}

			if !nextCADirExists(t, dataDir) {
				t.Fatal("ca.next must be preserved: alpha's authorized_keys write was issued, it may trust only the new CA")
			}
			sawPreserve := false
			for _, e := range events {
				if e.Type == EventWarn && strings.Contains(e.Msg, "MUST be preserved") {
					sawPreserve = true
				}
			}
			if !sawPreserve {
				t.Fatalf("expected the MUST-be-preserved recovery warning; events=%+v", events)
			}

			// ca.next survives, so the DB-only cert must NOT be rolled back.
			cl, err := d.GetPeer(ctx, "aa-client")
			if err != nil {
				t.Fatalf("GetPeer aa-client: %v", err)
			}
			if bytes.Equal(cl.Cert, priorCert) || cl.Serial == 7 {
				t.Fatal("skip-notice cert must not be rolled back while ca.next is preserved")
			}
		})
	}
}

// TestRekeyAbortAfterPreWriteFailureCleansStagingDir: a push failing at dial or
// at the authorized_keys read never touched the peer's trust root, so it must
// not count as rotated — a later abort still removes ca.next (T150 behavior).
func TestRekeyAbortAfterPreWriteFailureCleansStagingDir(t *testing.T) {
	for _, failOp := range []string{"dial", "read"} {
		t.Run(failOp, func(t *testing.T) {
			dataDir, d := setupOpsEnv(t, "alpha", "mgr")
			ctx := context.Background()
			rekeyAbortInsertCorruptPeer(t, d, "zz-corrupt")

			dialer := &rekeyAbortDialer{
				inner:    &fakeDialer{},
				failHost: "alpha",
				failOp:   failOp,
				failErr:  errors.New("simulated " + failOp + " failure"),
			}
			var events []Event
			deps := rekeyAbortDeps(dataDir, d, dialer.dial, &events)

			err := Rekey(ctx, deps, RekeyOptions{Hostname: "mgr"})
			if err == nil || !strings.HasPrefix(err.Error(), "parse pubkey for zz-corrupt: ") {
				t.Fatalf("err = %v, want parse-pubkey abort cause", err)
			}

			if nextCADirExists(t, dataDir) {
				t.Fatal("ca.next must be removed: alpha failed before any trust-root write")
			}
			for _, e := range events {
				if e.Type == EventWarn && strings.Contains(e.Msg, "MUST be preserved") {
					t.Errorf("no recovery warning expected when nothing was rotated: %q", e.Msg)
				}
			}
		})
	}
}

// TestRekeyCleanAbortRestoresDBOnlyCerts: a skip-notice (client-style) peer's
// cert is updated DB-only before the abort; when the abort discards ca.next,
// that cert would be a /pull-served orphan signed by a deleted CA, so the
// cleanup must restore the pre-rekey cert and serial.
func TestRekeyCleanAbortRestoresDBOnlyCerts(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "mgr")
	ctx := context.Background()
	priorCert := []byte("prior-client-cert")
	rekeyAbortInsertClientPeer(t, d, "aa-client", priorCert, 7)
	rekeyAbortInsertCorruptPeer(t, d, "zz-corrupt")

	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	err := Rekey(ctx, deps, RekeyOptions{Hostname: "mgr"})
	if err == nil || !strings.HasPrefix(err.Error(), "parse pubkey for zz-corrupt: ") {
		t.Fatalf("err = %v, want parse-pubkey abort cause", err)
	}

	// The skip-notice branch must have minted before the abort, proving the
	// restore below actually undid an overwrite.
	sawClientDone := false
	for _, e := range events {
		if e.Type == EventPeerDone && e.Peer == "aa-client" {
			sawClientDone = true
		}
	}
	if !sawClientDone {
		t.Fatal("aa-client's DB-only cert update should have happened before the abort")
	}

	if nextCADirExists(t, dataDir) {
		t.Fatal("ca.next must be removed on a clean abort")
	}
	p, err := d.GetPeer(ctx, "aa-client")
	if err != nil {
		t.Fatalf("GetPeer aa-client: %v", err)
	}
	if !bytes.Equal(p.Cert, priorCert) || p.Serial != 7 {
		t.Fatalf("aa-client cert/serial not restored: serial=%d cert=%q", p.Serial, p.Cert)
	}
	for _, e := range events {
		if e.Type == EventWarn && strings.Contains(e.Msg, "failed to restore") {
			t.Errorf("unexpected restore-failure warning: %q", e.Msg)
		}
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
