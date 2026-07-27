package ops

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/sshpush"
)

func TestProbeAndCaptureHostKeyReachable(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "peer1")
	ctx := context.Background()
	dialer := &fakeDialer{}
	deps := Deps{DB: d, DataDir: dataDir, Dial: dialer.dial}

	reachable, err := ProbeAndCaptureHostKey(ctx, deps, "peer1", "10.0.0.5", "root")
	if err != nil {
		t.Fatalf("ProbeAndCaptureHostKey: %v", err)
	}
	if !reachable {
		t.Fatal("a successful dial should mark the peer reachable")
	}
	if !dialer.captureSeen {
		t.Fatal("the probe dial must request host-key capture")
	}
	p, err := d.GetPeer(ctx, "peer1")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if !p.PushReachable {
		t.Fatal("peer should be persisted PushReachable=true")
	}
}

func TestProbeAndCaptureHostKeyUnreachable(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "peer1")
	ctx := context.Background()
	dialer := &fakeDialer{failDial: map[string]error{"10.0.0.5": errors.New("dial tcp: connection refused")}}
	deps := Deps{DB: d, DataDir: dataDir, Dial: dialer.dial}

	reachable, err := ProbeAndCaptureHostKey(ctx, deps, "peer1", "10.0.0.5", "root")
	if err == nil {
		t.Fatal("an unreachable peer should return the dial error (non-fatal to caller)")
	}
	if reachable {
		t.Fatal("an unreachable peer must not be marked reachable")
	}
	p, err := d.GetPeer(ctx, "peer1")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.PushReachable {
		t.Fatal("peer should be persisted PushReachable=false after a failed probe")
	}
}

// TestUpdatePeerSkipsUnreachable verifies the push-skip extension end to end:
// a normal (inbound) peer marked push-unreachable is NOT dialed by UpdatePeer;
// the DB-side cert change still lands and the self-fetch notice is emitted.
func TestUpdatePeerSkipsUnreachable(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "peer1")
	ctx := context.Background()
	if err := d.SetPeerReachable(ctx, "peer1", false); err != nil {
		t.Fatalf("SetPeerReachable: %v", err)
	}
	dialer := &fakeDialer{}
	var events []Event
	deps := collectingDeps(dataDir, d, dialer, &events)

	if err := UpdatePeer(ctx, deps, "peer1", []string{"infra"}, "", "mgr"); err != nil {
		t.Fatalf("UpdatePeer: %v", err)
	}
	if len(dialer.dialedHosts) != 0 {
		t.Fatalf("push-unreachable peer must not be dialed, dialed: %v", dialer.dialedHosts)
	}
	if len(dialer.snapshot()) != 0 {
		t.Fatalf("push-unreachable peer must receive no push ops: %+v", dialer.snapshot())
	}
	var sawNotice bool
	for _, e := range events {
		if e.Type == EventInfo && strings.Contains(e.Msg, "push-unreachable") {
			sawNotice = true
		}
	}
	if !sawNotice {
		t.Fatalf("expected a push-unreachable self-fetch notice, events: %+v", events)
	}
	// The cert change must still be persisted (delivered later via pull).
	p, err := d.GetPeer(ctx, "peer1")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if len(p.Cert) == 0 {
		t.Fatal("cert should be re-signed and stored even when push is skipped")
	}
}

// TestProbeAndCaptureHostKeyTimeoutStillRecords guards the bug where an
// unreachable dial burns the whole context deadline, so reusing that expired
// context for the SetPeerReachable write failed and left the peer at its
// default push_reachable=1. The reachability write must use a fresh context.
func TestProbeAndCaptureHostKeyTimeoutStillRecords(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "peer1")
	// Emulate a dial that fails because its context already expired — exactly
	// what a real dial to an unroutable address yields once the timeout elapses.
	dialFn := func(dctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		return nil, context.DeadlineExceeded
	}
	deps := Deps{DB: d, DataDir: dataDir, Dial: dialFn}

	// Pass an ALREADY-expired probe context. The reachability WRITE must not
	// inherit it (a Dial that burns the deadline leaves ctx expired); the
	// returned error is the dial error, but the DB verdict must still land.
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	reachable, _ := ProbeAndCaptureHostKey(ctx, deps, "peer1", "10.255.255.1", "root")
	if reachable {
		t.Fatal("a timed-out dial must mark the peer unreachable")
	}
	// The real contract: the verdict is persisted even though the probe ctx
	// expired. (Before the fix, the write reused the expired ctx and failed,
	// silently leaving push_reachable at its default 1.)
	p, err := d.GetPeer(context.Background(), "peer1")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.PushReachable {
		t.Fatal("peer must be persisted push_reachable=false after a timed-out dial")
	}
}

// TestProbeAndCaptureHostKeySlowDialStillRecords is the e2e regression: the dial
// to an unreachable host runs until the probe context's deadline elapses, so a
// write context that SPANNED the dial would already be expired. The verdict must
// still be persisted (write context is created after the dial).
func TestProbeAndCaptureHostKeySlowDialStillRecords(t *testing.T) {
	dataDir, d := setupOpsEnv(t, "peer1")
	// Dial blocks until the probe ctx deadline, then fails — like a real TCP
	// dial to an unroutable address that times out.
	dialFn := func(dctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		<-dctx.Done()
		return nil, dctx.Err()
	}
	deps := Deps{DB: d, DataDir: dataDir, Dial: dialFn}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	reachable, _ := ProbeAndCaptureHostKey(ctx, deps, "peer1", "10.255.255.1", "root")
	if reachable {
		t.Fatal("a timed-out dial must mark the peer unreachable")
	}
	p, err := d.GetPeer(context.Background(), "peer1")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.PushReachable {
		t.Fatal("verdict must be persisted even when the dial consumed the whole probe deadline")
	}
}

func TestSkipPushNotice(t *testing.T) {
	cases := []struct {
		name      string
		peer      db.Peer
		wantSkip  bool
		wantSubst string
	}{
		{"inbound reachable -> push", db.Peer{Name: "a", Inbound: true, PushReachable: true}, false, ""},
		{"client-style -> self-fetch", db.Peer{Name: "b", Inbound: false, PushReachable: true}, true, "certhold-cli refresh"},
		{"push-unreachable -> self-fetch", db.Peer{Name: "c", Inbound: true, PushReachable: false}, true, "push-unreachable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.peer
			skip, notice := skipPushNotice(&p)
			if skip != tc.wantSkip {
				t.Fatalf("skip = %v, want %v", skip, tc.wantSkip)
			}
			if tc.wantSubst != "" && !strings.Contains(notice, tc.wantSubst) {
				t.Fatalf("notice %q missing %q", notice, tc.wantSubst)
			}
		})
	}
}
