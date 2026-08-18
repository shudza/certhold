package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/peerfiles"
	"github.com/shudza/certhold/internal/sshpush"
)

type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func TestServeStartupAndShutdown(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "state.db")

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}
	if _, err := ca.Generate(filepath.Join(tempDir, "ca")); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}

	cmd := NewRootCmd()
	out := &syncBuf{}
	errBuf := &syncBuf{}
	cmd.SetOut(out)
	cmd.SetErr(errBuf)
	cmd.SetArgs([]string{
		"--db", dbPath,
		"--data-dir", tempDir,
		"serve",
		"--addr", "127.0.0.1:0",
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- cmd.ExecuteContext(ctx)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if bytes.Contains([]byte(out.String()), []byte("listening")) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	got := out.String()
	if !strings.Contains(got, "listening") {
		cancel()
		<-done
		t.Fatalf("server never printed listening line; out=%q errBuf=%q", got, errBuf.String())
	}
	if !strings.Contains(got, "https://") {
		t.Errorf("expected 'https://' in startup output; got %q", got)
	}
	if !strings.Contains(got, "cert SHA256:") {
		t.Errorf("expected 'cert SHA256:' line in startup output; got %q", got)
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve returned error: %v (errBuf=%q)", err, errBuf.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not shut down within timeout")
	}
}

func TestServeAutoTLSAcceptsHTTPSHandshake(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "state.db")

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}
	if _, err := ca.Generate(filepath.Join(tempDir, "ca")); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}

	cmd := NewRootCmd()
	out := &syncBuf{}
	errBuf := &syncBuf{}
	cmd.SetOut(out)
	cmd.SetErr(errBuf)
	cmd.SetArgs([]string{
		"--db", dbPath,
		"--data-dir", tempDir,
		"serve",
		"--addr", "127.0.0.1:0",
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- cmd.ExecuteContext(ctx)
	}()

	var addr string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s := out.String()
		if i := strings.Index(s, "https://"); i >= 0 {
			rest := s[i+len("https://"):]
			if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
				addr = strings.TrimSpace(rest[:nl])
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if addr == "" {
		cancel()
		<-done
		t.Fatalf("could not parse addr from output: %q", out.String())
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		cancel()
		<-done
		t.Fatalf("TLS GET failed: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve returned error: %v (errBuf=%q)", err, errBuf.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not shut down within timeout")
	}
}

func seedReachableTestPeer(t *testing.T, dataDir string) *db.DB {
	t.Helper()
	if _, err := ca.Generate(filepath.Join(dataDir, "ca")); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	d, err := db.Open(filepath.Join(dataDir, "state.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if err := d.InsertPeer(context.Background(), "p1", 1, "fp", []byte("k"), "root", true, "tok"); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	return d
}

func TestEnrollReachabilityProbeRetriesThenMarksUnreachable(t *testing.T) {
	dataDir := t.TempDir()
	d := seedReachableTestPeer(t, dataDir)

	origDial, origRetries, origBackoff := serveDial, probeRetries, probeBackoff
	t.Cleanup(func() { serveDial, probeRetries, probeBackoff = origDial, origRetries, origBackoff })

	var dials int
	probeRetries = 3
	probeBackoff = time.Millisecond
	serveDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		dials++
		if !opts.CaptureHostKey {
			t.Errorf("probe dial must request host-key capture")
		}
		return nil, errors.New("dial tcp: connection refused")
	}

	probe := enrollReachabilityProbe(d, dataDir)
	probe("p1", "10.0.0.9", "root")

	if dials != probeRetries {
		t.Errorf("dials = %d, want %d (one per retry)", dials, probeRetries)
	}
	p, err := d.GetPeer(context.Background(), "p1")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.PushReachable {
		t.Fatal("peer should be marked push-unreachable after all retries fail")
	}
}

func TestEnrollReachabilityProbeMarksReachableOnFirstSuccess(t *testing.T) {
	dataDir := t.TempDir()
	d := seedReachableTestPeer(t, dataDir)
	// Pre-mark unreachable so we can observe the probe flip it back to true.
	if err := d.SetPeerReachable(context.Background(), "p1", false); err != nil {
		t.Fatalf("SetPeerReachable: %v", err)
	}

	origDial, origRetries := serveDial, probeRetries
	t.Cleanup(func() { serveDial, probeRetries = origDial, origRetries })

	var dials int
	probeRetries = 3
	serveDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		dials++
		return stubPusher{}, nil
	}

	enrollReachabilityProbe(d, dataDir)("p1", "10.0.0.9", "root")

	if dials != 1 {
		t.Errorf("dials = %d, want 1 (stop after first success)", dials)
	}
	p, _ := d.GetPeer(context.Background(), "p1")
	if !p.PushReachable {
		t.Fatal("a successful probe should mark the peer reachable")
	}
}

type stubPusher struct{}

func (stubPusher) WriteFileAtomic(context.Context, string, []byte, fs.FileMode) error { return nil }
func (stubPusher) ReadFile(context.Context, string) ([]byte, error)                   { return nil, nil }
func (stubPusher) SpliceConfigBlock(context.Context, string, string, string) error    { return nil }
func (stubPusher) ClearPeer(context.Context, peerfiles.RemotePaths, string, []ssh.PublicKey) error {
	return nil
}
func (stubPusher) ReloadSSHD(context.Context) error   { return nil }
func (stubPusher) VerifyHealth(context.Context) error { return nil }
func (stubPusher) Close() error                       { return nil }

// TestEnrollReachabilityProbeRealDialUnreachable exercises the FULL serve-side
// probe path (real sshpush.Dial, real manager self files from init) against an
// unreachable address — the e2e non-bidirectional case. It must not panic and
// must mark the peer push-unreachable. (Regression guard: the probe goroutine
// once panicked here, which the handler now also recovers from.)
func TestEnrollReachabilityProbeRealDialUnreachable(t *testing.T) {
	t.Setenv(envCAPassphrase, "test-ca-pw")
	t.Setenv(envPeerPassphrase, "test-peer-pw")
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "state.db")

	// init names the manager self peer after --hostname and persists it (the
	// self_name meta key), so the probe resolves the self row and its real
	// cert/key even though this name never matches the machine hostname.
	icmd := NewRootCmd()
	var iout bytes.Buffer
	icmd.SetOut(&iout)
	icmd.SetErr(&iout)
	icmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "init", "--hostname", "mgr-probe", "--user", "root", "--listen-ip", "127.0.0.1", "--no-prompt"})
	if err := icmd.Execute(); err != nil {
		t.Fatalf("init: %v\n%s", err, iout.String())
	}

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	ctx := context.Background()
	if err := d.InsertPeer(ctx, "isolated01", 1, "fp", []byte("k"), "root", true, "tok"); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}

	origRetries, origBackoff := probeRetries, probeBackoff
	t.Cleanup(func() { probeRetries, probeBackoff = origRetries, origBackoff })
	probeRetries, probeBackoff = 1, time.Millisecond

	// 192.0.2.0/24 (TEST-NET-1) is reserved and unroutable: the dial fails fast
	// without hitting a real host, modeling a non-bidirectional peer.
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if rec := recover(); rec != nil {
				t.Errorf("probe panicked (must be panic-free): %v", rec)
			}
		}()
		enrollReachabilityProbe(d, dataDir)("isolated01", "192.0.2.1", "root")
	}()
	select {
	case <-done:
	case <-time.After(90 * time.Second):
		t.Fatal("probe did not finish in time")
	}

	p, err := d.GetPeer(ctx, "isolated01")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if p.PushReachable {
		t.Fatal("unreachable peer must be marked push_reachable=false by the real-dial probe")
	}
}

func TestServeMismatchedTLSFlags(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "state.db")

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}
	if _, err := ca.Generate(filepath.Join(tempDir, "ca")); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}

	cmd := NewRootCmd()
	out := &syncBuf{}
	errBuf := &syncBuf{}
	cmd.SetOut(out)
	cmd.SetErr(errBuf)
	cmd.SetArgs([]string{
		"--db", dbPath,
		"--data-dir", tempDir,
		"serve",
		"--addr", "127.0.0.1:0",
		"--tls-cert", "/tmp/nonexistent.crt",
	})

	err = cmd.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("expected error for mismatched TLS flags")
	}
	if !strings.Contains(err.Error(), "must be provided together") {
		t.Errorf("error = %q, want substring 'must be provided together'", err.Error())
	}
}
