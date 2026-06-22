package ops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/peerfiles"
	"github.com/shudza/certhold/internal/sshpush"
)

type fakeCall struct {
	host    string
	op      string
	path    string
	content []byte
}

type fakeDialer struct {
	mu          sync.Mutex
	calls       []fakeCall
	failDial    map[string]error
	clearErr    map[string]error
	readData    map[string][]byte
	dialedHosts []string
	captureSeen bool
}

func (f *fakeDialer) dial(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dialedHosts = append(f.dialedHosts, host)
	if opts.CaptureHostKey {
		f.captureSeen = true
	}
	if err, ok := f.failDial[host]; ok {
		return nil, err
	}
	return &fakePusher{host: host, d: f}, nil
}

func (f *fakeDialer) snapshot() []fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakeCall, len(f.calls))
	copy(out, f.calls)
	return out
}

type fakePusher struct {
	host string
	d    *fakeDialer
}

func (p *fakePusher) record(op, path string, content []byte) {
	p.d.mu.Lock()
	defer p.d.mu.Unlock()
	p.d.calls = append(p.d.calls, fakeCall{host: p.host, op: op, path: path, content: append([]byte(nil), content...)})
}

func (p *fakePusher) WriteFileAtomic(ctx context.Context, remotePath string, content []byte, mode fs.FileMode) error {
	p.record("write", remotePath, content)
	return nil
}

func (p *fakePusher) ReadFile(ctx context.Context, remotePath string) ([]byte, error) {
	p.record("read", remotePath, nil)
	p.d.mu.Lock()
	defer p.d.mu.Unlock()
	if b, ok := p.d.readData[remotePath]; ok {
		return append([]byte(nil), b...), nil
	}
	return nil, nil
}

func (p *fakePusher) SpliceConfigBlock(ctx context.Context, configPath, instanceKey, block string) error {
	p.record("splice", configPath, []byte(block))
	return nil
}

func (p *fakePusher) ClearPeer(ctx context.Context, paths peerfiles.RemotePaths, instanceKey string, caPubKey ssh.PublicKey) error {
	p.d.mu.Lock()
	clearErr := p.d.clearErr[p.host]
	p.d.mu.Unlock()
	p.record("clear", paths.ConfigTarget, nil)
	return clearErr
}

func (p *fakePusher) ReloadSSHD(ctx context.Context) error {
	p.record("reload", "", nil)
	return nil
}

func (p *fakePusher) VerifyHealth(ctx context.Context) error {
	p.record("verify", "", nil)
	return nil
}

func (p *fakePusher) Close() error { return nil }

// setupOpsEnv builds a plaintext CA + db with an instance key and the named
// inbound root peers, each in group "infra" with "infra" allowed.
func setupOpsEnv(t *testing.T, names ...string) (dataDir string, d *db.DB) {
	t.Helper()
	dataDir = t.TempDir()
	if _, err := ca.Generate(filepath.Join(dataDir, "ca")); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	d, err := db.Open(filepath.Join(dataDir, "state.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	ctx := context.Background()
	if _, err := EnsureInstanceKey(ctx, d); err != nil {
		t.Fatalf("EnsureInstanceKey: %v", err)
	}
	if err := d.EnsureGroup(ctx, "infra"); err != nil {
		t.Fatalf("EnsureGroup: %v", err)
	}
	for _, name := range names {
		_, pubAuth, sshPub, err := ca.GeneratePeerKey()
		if err != nil {
			t.Fatalf("GeneratePeerKey %s: %v", name, err)
		}
		if err := d.InsertPeer(ctx, name, 100, ssh.FingerprintSHA256(sshPub), pubAuth, "root", true, ""); err != nil {
			t.Fatalf("InsertPeer %s: %v", name, err)
		}
		if err := d.SetPeerGroups(ctx, name, []string{"infra"}); err != nil {
			t.Fatalf("SetPeerGroups %s: %v", name, err)
		}
		if err := d.SetPeerAllowedGroups(ctx, name, []string{"infra"}); err != nil {
			t.Fatalf("SetPeerAllowedGroups %s: %v", name, err)
		}
	}
	return dataDir, d
}

func collectingDeps(dataDir string, d *db.DB, dialer *fakeDialer, events *[]Event) Deps {
	return Deps{
		DB:      d,
		DataDir: dataDir,
		Dial:    dialer.dial,
		OnEvent: func(e Event) { *events = append(*events, e) },
	}
}

func eventTypes(events []Event) []EventType {
	out := make([]EventType, len(events))
	for i, e := range events {
		out[i] = e.Type
	}
	return out
}

func TestUpdatePeerEventStreamSuccess(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "peer1")
	ctx := context.Background()
	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	if err := UpdatePeer(ctx, deps, "peer1", []string{"infra"}, ""); err != nil {
		t.Fatalf("UpdatePeer: %v", err)
	}

	p, err := d.GetPeer(ctx, "peer1")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	want := []Event{
		{Type: EventPeerStart, Peer: "peer1"},
		{Type: EventPeerDone, Peer: "peer1", Msg: fmt.Sprintf("updated peer1 (serial %d)", p.Serial)},
	}
	if len(events) != len(want) {
		t.Fatalf("events = %+v, want %+v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Errorf("event[%d] = %+v, want %+v", i, events[i], want[i])
		}
	}

	calls := dialer.snapshot()
	if len(calls) != 3 || calls[0].op != "write" || calls[1].op != "splice" || calls[2].op != "verify" {
		t.Errorf("push calls = %+v, want write/splice/verify", calls)
	}
}

func TestUpdatePeerClientPeerEvents(t *testing.T) {
	dataDir, d := setupOpsEnv(t)
	ctx := context.Background()
	_, pubAuth, sshPub, err := ca.GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey: %v", err)
	}
	if err := d.InsertPeer(ctx, "laptop", 1, ssh.FingerprintSHA256(sshPub), pubAuth, "alice", false, "tok"); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}

	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	if err := UpdatePeer(ctx, deps, "laptop", []string{"infra"}, ""); err != nil {
		t.Fatalf("UpdatePeer: %v", err)
	}
	if calls := dialer.snapshot(); len(calls) != 0 {
		t.Errorf("client peer must not be dialed; calls=%+v", calls)
	}

	p, err := d.GetPeer(ctx, "laptop")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	want := []Event{
		{Type: EventInfo, Peer: "laptop", Msg: "client peer laptop: changes pending until 'certhold-cli refresh' runs on it"},
		{Type: EventPeerDone, Peer: "laptop", Msg: fmt.Sprintf("updated laptop (serial %d)", p.Serial)},
	}
	if len(events) != len(want) {
		t.Fatalf("events = %+v, want %+v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Errorf("event[%d] = %+v, want %+v", i, events[i], want[i])
		}
	}
}

func TestUpdatePeerPushFailureEmitsPeerFailed(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "peer1")
	ctx := context.Background()
	dialer := &fakeDialer{failDial: map[string]error{"peer1": errors.New("boom")}}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	err := UpdatePeer(ctx, deps, "peer1", []string{"infra"}, "")
	if err == nil {
		t.Fatal("expected dial error")
	}
	if got, want := err.Error(), "ssh dial peer1: boom"; got != want {
		t.Errorf("err = %q, want %q", got, want)
	}

	if got := eventTypes(events); len(got) != 2 || got[0] != EventPeerStart || got[1] != EventPeerFailed {
		t.Fatalf("event types = %v, want [PeerStart PeerFailed]; events=%+v", got, events)
	}
	failed := events[1]
	if failed.Peer != "peer1" || failed.Err == nil || failed.Err.Error() != "ssh dial peer1: boom" {
		t.Errorf("EventPeerFailed = %+v, want Peer=peer1 Err=%q", failed, "ssh dial peer1: boom")
	}
}

func TestRekeyEventStreamSuccess(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "alpha", "beta", "mgr")
	ctx := context.Background()
	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	if err := Rekey(ctx, deps, RekeyOptions{Hostname: "mgr"}); err != nil {
		t.Fatalf("Rekey: %v", err)
	}

	serial := func(name string) uint64 {
		t.Helper()
		p, err := d.GetPeer(ctx, name)
		if err != nil {
			t.Fatalf("GetPeer %s: %v", name, err)
		}
		return p.Serial
	}
	want := []Event{
		{Type: EventPeerStart, Peer: "alpha"},
		{Type: EventPeerDone, Peer: "alpha", Msg: fmt.Sprintf("rekeyed alpha (serial %d)", serial("alpha"))},
		{Type: EventPeerStart, Peer: "beta"},
		{Type: EventPeerDone, Peer: "beta", Msg: fmt.Sprintf("rekeyed beta (serial %d)", serial("beta"))},
		{Type: EventPeerDone, Peer: "mgr", Msg: fmt.Sprintf("rekeyed mgr (serial %d)", serial("mgr"))},
	}
	if len(events) != len(want)+1 {
		t.Fatalf("events = %+v, want %d peer events + summary", events, len(want))
	}
	for i := range want {
		if events[i] != want[i] {
			t.Errorf("event[%d] = %+v, want %+v", i, events[i], want[i])
		}
	}
	summary := events[len(events)-1]
	if summary.Type != EventInfo || !strings.HasPrefix(summary.Msg, "Rekey complete: 3 peers rotated, CA version 1 active, old CA archived at ") {
		t.Errorf("summary event = %+v", summary)
	}
	for _, e := range events {
		if e.Type == EventWarn || e.Type == EventPeerFailed {
			t.Errorf("unexpected warn/failed event on success path: %+v", e)
		}
	}
}

func TestRekeyStragglerPartialFailure(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "alpha", "beta", "mgr")
	ctx := context.Background()
	dialer := &fakeDialer{failDial: map[string]error{"beta": errors.New("connection refused")}}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	if err := Rekey(ctx, deps, RekeyOptions{Hostname: "mgr"}); err != nil {
		t.Fatalf("Rekey must return nil on partial failure, got %v", err)
	}

	var failed []Event
	var warns []Event
	for _, e := range events {
		switch e.Type {
		case EventPeerFailed:
			failed = append(failed, e)
		case EventWarn:
			warns = append(warns, e)
		}
	}
	if len(failed) != 1 || failed[0].Peer != "beta" || failed[0].Err == nil || failed[0].Err.Error() != "dial: connection refused" {
		t.Fatalf("EventPeerFailed = %+v, want one for beta with %q", failed, "dial: connection refused")
	}

	wantWarns := []string{
		"\nWARNING: rekey could not reach 1 peer(s); they STILL TRUST THE PREVIOUS CA and were NOT rotated:",
		"  - beta: dial: connection refused",
	}
	if len(warns) != 4 {
		t.Fatalf("warn events = %+v, want 4 lines", warns)
	}
	for i, wantMsg := range wantWarns {
		if warns[i].Msg != wantMsg {
			t.Errorf("warn[%d].Msg = %q, want %q", i, warns[i].Msg, wantMsg)
		}
	}
	if warns[1].Peer != "beta" {
		t.Errorf("per-peer warn line should name the peer: %+v", warns[1])
	}
	if !strings.Contains(warns[2].Msg, filepath.Join(dataDir, "ca.old.")) {
		t.Errorf("recovery warn should name the archived old CA dir: %q", warns[2].Msg)
	}

	var summary *Event
	for i := range events {
		if events[i].Type == EventInfo {
			summary = &events[i]
		}
	}
	if summary == nil || !strings.HasPrefix(summary.Msg, "Rekey complete: 2 peers rotated, CA version 1 active") {
		t.Errorf("summary = %+v, want 2 peers rotated", summary)
	}

	beta, err := d.GetPeer(ctx, "beta")
	if err != nil {
		t.Fatalf("GetPeer beta: %v", err)
	}
	if beta.Serial != 100 {
		t.Errorf("straggler beta cert_serial bumped to %d; must stay 100", beta.Serial)
	}
	for _, c := range dialer.snapshot() {
		if c.host == "beta" {
			t.Errorf("unreachable beta must not receive pushes: %+v", c)
		}
	}
}

func TestRekeyAbortEmitsWarnAndReturnsCause(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "alpha", "beta", "mgr")
	ctx := context.Background()
	if err := d.InsertPeer(ctx, "zz-corrupt", 1, "fp-garbage", []byte("not a valid authorized key"), "root", true, ""); err != nil {
		t.Fatalf("InsertPeer corrupt: %v", err)
	}
	oldCAPub, err := os.ReadFile(filepath.Join(dataDir, "ca", "ca.pub"))
	if err != nil {
		t.Fatalf("read ca.pub: %v", err)
	}

	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	err = Rekey(ctx, deps, RekeyOptions{Hostname: "mgr"})
	if err == nil {
		t.Fatal("expected abort error")
	}
	if !strings.HasPrefix(err.Error(), "parse pubkey for zz-corrupt: ") {
		t.Errorf("err = %q, want parse pubkey cause", err)
	}

	var warns []Event
	for _, e := range events {
		if e.Type == EventWarn {
			warns = append(warns, e)
		}
	}
	if len(warns) != 3 {
		t.Fatalf("warn events = %+v, want abort + already-rotated + staging-dir recovery lines", warns)
	}
	if want := fmt.Sprintf("rekey aborted: %v", err); warns[0].Msg != want {
		t.Errorf("warn[0].Msg = %q, want %q", warns[0].Msg, want)
	}
	if want := "peers already rotated to new CA (recovery may be required): [alpha beta]"; warns[1].Msg != want {
		t.Errorf("warn[1].Msg = %q, want %q", warns[1].Msg, want)
	}
	if !strings.Contains(warns[2].Msg, filepath.Join(dataDir, "ca.next")) || !strings.Contains(warns[2].Msg, "Manual recovery is required") {
		t.Errorf("warn[2].Msg should name the staged ca.next and require manual recovery: %q", warns[2].Msg)
	}

	caPubAfter, err := os.ReadFile(filepath.Join(dataDir, "ca", "ca.pub"))
	if err != nil {
		t.Fatalf("read ca.pub after: %v", err)
	}
	if !bytes.Equal(caPubAfter, oldCAPub) {
		t.Error("CA was swapped despite abort")
	}
}

// TestRevokeDefaultClearsAndDeletes covers the default (rekey=false) path: a
// reachable inbound peer is dialed, ClearPeer is invoked, and its row is then
// deleted.
func TestRevokeDefaultClearsAndDeletes(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "alpha", "beta", "mgr")
	ctx := context.Background()
	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	if err := RevokePeer(ctx, deps, "alpha", "mgr", false); err != nil {
		t.Fatalf("RevokePeer: %v", err)
	}

	if _, err := d.GetPeer(ctx, "alpha"); !errors.Is(err, db.ErrPeerNotFound) {
		t.Errorf("alpha row should be deleted, got err=%v", err)
	}
	// beta must be untouched: a clean clear+delete is single-peer, no rotation.
	if _, err := d.GetPeer(ctx, "beta"); err != nil {
		t.Errorf("beta should be untouched: %v", err)
	}

	sawClear := false
	for _, c := range dialer.snapshot() {
		if c.host != "alpha" {
			t.Errorf("only alpha should be dialed, got %+v", c)
		}
		if c.op == "clear" {
			sawClear = true
		}
	}
	if !sawClear {
		t.Error("ClearPeer was not called on alpha")
	}
	if got := dialer.dialedHosts; len(got) != 1 || got[0] != "alpha" {
		t.Errorf("dialedHosts = %v, want [alpha]", got)
	}
}

// TestRevokeDefaultClientPeerErrorsWithoutDial: a no-inbound/client peer is
// rejected before any dial and its row is preserved.
func TestRevokeDefaultClientPeerErrorsWithoutDial(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "mgr")
	ctx := context.Background()
	_, pubAuth, sshPub, err := ca.GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey: %v", err)
	}
	if err := d.InsertPeer(ctx, "laptop", 1, ssh.FingerprintSHA256(sshPub), pubAuth, "alice", false, "tok"); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	err = RevokePeer(ctx, deps, "laptop", "mgr", false)
	if err == nil {
		t.Fatal("expected error for client peer default revoke")
	}
	if !strings.Contains(err.Error(), "remove") || !strings.Contains(err.Error(), "--rekey") {
		t.Errorf("err should guide to remove/--rekey, got %q", err)
	}
	if len(dialer.dialedHosts) != 0 {
		t.Errorf("client peer must not be dialed, got %v", dialer.dialedHosts)
	}
	if _, err := d.GetPeer(ctx, "laptop"); err != nil {
		t.Errorf("client peer row must be preserved: %v", err)
	}
}

// TestRevokeDefaultDialFailurePreservesRow: a failed dial returns an error and
// does NOT delete the row.
func TestRevokeDefaultDialFailurePreservesRow(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "alpha", "mgr")
	ctx := context.Background()
	dialer := &fakeDialer{failDial: map[string]error{"alpha": errors.New("connection refused")}}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	err := RevokePeer(ctx, deps, "alpha", "mgr", false)
	if err == nil {
		t.Fatal("expected dial error")
	}
	if !strings.Contains(err.Error(), "NOT deleted") {
		t.Errorf("err should say row not deleted, got %q", err)
	}
	if _, err := d.GetPeer(ctx, "alpha"); err != nil {
		t.Errorf("alpha row must be preserved on dial failure: %v", err)
	}
}

// TestRevokeDefaultClearFailurePreservesRow: a dial that succeeds but ClearPeer
// fails returns an error and does NOT delete the row.
func TestRevokeDefaultClearFailurePreservesRow(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "alpha", "mgr")
	ctx := context.Background()
	dialer := &fakeDialer{clearErr: map[string]error{"alpha": errors.New("permission denied")}}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	err := RevokePeer(ctx, deps, "alpha", "mgr", false)
	if err == nil {
		t.Fatal("expected clear error")
	}
	if !strings.Contains(err.Error(), "NOT deleted") {
		t.Errorf("err should say row not deleted, got %q", err)
	}
	if _, err := d.GetPeer(ctx, "alpha"); err != nil {
		t.Errorf("alpha row must be preserved on clear failure: %v", err)
	}
}

// TestRevokeRekeyRotatesAndDeletes covers the --rekey path: the revoked peer is
// deleted, the remaining peers are re-signed, and the manager + remaining peers
// can still authenticate against the rotated CA (no trust-root lockout).
func TestRevokeRekeyRotatesAndDeletes(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "alpha", "beta", "mgr")
	ctx := context.Background()

	oldCAPub, err := os.ReadFile(filepath.Join(dataDir, "ca", "ca.pub"))
	if err != nil {
		t.Fatalf("read old ca.pub: %v", err)
	}

	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	if err := RevokePeer(ctx, deps, "alpha", "mgr", true); err != nil {
		t.Fatalf("RevokePeer --rekey: %v", err)
	}

	if _, err := d.GetPeer(ctx, "alpha"); !errors.Is(err, db.ErrPeerNotFound) {
		t.Errorf("alpha row should be deleted, got err=%v", err)
	}
	for _, c := range dialer.snapshot() {
		if c.host == "alpha" {
			t.Errorf("revoked alpha must never be contacted: %+v", c)
		}
	}

	// The CA was rotated: ca.pub changed.
	newCAPub, err := os.ReadFile(filepath.Join(dataDir, "ca", "ca.pub"))
	if err != nil {
		t.Fatalf("read new ca.pub: %v", err)
	}
	if bytes.Equal(newCAPub, oldCAPub) {
		t.Fatal("CA public key did not change after --rekey revoke")
	}

	newCAKey, _, _, _, err := ssh.ParseAuthorizedKey(newCAPub)
	if err != nil {
		t.Fatalf("parse new ca.pub: %v", err)
	}
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), newCAKey.Marshal())
		},
	}
	// No trust-root lockout: every remaining peer (mgr included, beta) holds a
	// cert that validates against the NEW CA on its declared principals.
	for _, name := range []string{"beta", "mgr"} {
		p, err := d.GetPeer(ctx, name)
		if err != nil {
			t.Fatalf("GetPeer %s: %v", name, err)
		}
		if len(p.Cert) == 0 {
			t.Fatalf("%s has no stored cert after rotation", name)
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey(p.Cert)
		if err != nil {
			t.Fatalf("parse %s cert: %v", name, err)
		}
		cert, ok := pk.(*ssh.Certificate)
		if !ok {
			t.Fatalf("%s stored material is not a certificate", name)
		}
		if err := checker.CheckCert(name, cert); err != nil {
			t.Errorf("%s cert does not validate against the rotated CA: %v", name, err)
		}
	}
}

func TestRevokePeerUnknownPeer(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "mgr")
	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	err := RevokePeer(context.Background(), deps, "ghost", "mgr", false)
	if err == nil {
		t.Fatal("expected error for unknown peer")
	}
	if !errors.Is(err, db.ErrPeerNotFound) {
		t.Errorf("err = %v, want wrapped db.ErrPeerNotFound", err)
	}
}
