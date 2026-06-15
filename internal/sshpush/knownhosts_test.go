package sshpush

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func testHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("new public key: %v", err)
	}
	return pk
}

func TestAppendKnownHostCreatesDirAndFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "self", ".ssh", "known_hosts")
	key := testHostKey(t)

	if err := AppendKnownHost(path, "10.0.0.5:22", key); err != nil {
		t.Fatalf("AppendKnownHost: %v", err)
	}

	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if di.Mode().Perm() != 0700 {
		t.Errorf("dir mode = %o, want 0700", di.Mode().Perm())
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if fi.Mode().Perm() != 0644 {
		t.Errorf("file mode = %o, want 0644", fi.Mode().Perm())
	}

	// The written line must be accepted by knownhosts.New on read, keyed by the
	// normalized host (bare host for the default :22 port).
	cb, err := knownhosts.New(path)
	if err != nil {
		t.Fatalf("knownhosts.New: %v", err)
	}
	if err := cb("10.0.0.5:22", &net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 22}, key); err != nil {
		t.Errorf("written entry not accepted: %v", err)
	}
}

func TestAppendKnownHostDedupes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	key := testHostKey(t)
	for i := 0; i < 3; i++ {
		if err := AppendKnownHost(path, "host.example", key); err != nil {
			t.Fatalf("AppendKnownHost #%d: %v", i, err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	n := strings.Count(strings.TrimSpace(string(b)), "\n") + 1
	if n != 1 {
		t.Errorf("known_hosts has %d lines, want 1 (deduped):\n%s", n, b)
	}
}

func TestAppendKnownHostSecondHostAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := AppendKnownHost(path, "a.example", testHostKey(t)); err != nil {
		t.Fatalf("append a: %v", err)
	}
	if err := AppendKnownHost(path, "b.example", testHostKey(t)); err != nil {
		t.Fatalf("append b: %v", err)
	}
	b, _ := os.ReadFile(path)
	lines := strings.Count(strings.TrimRight(string(b), "\n"), "\n") + 1
	if lines != 2 {
		t.Errorf("want 2 distinct host lines, got %d:\n%s", lines, b)
	}
}

func TestCapturingCallbackAcceptsUnknownRecordsKey(t *testing.T) {
	key := testHostKey(t)
	c := &capturingCallback{strict: func(string, net.Addr, ssh.PublicKey) error {
		return &knownhosts.KeyError{} // empty Want => unknown
	}}
	if err := c.callback("h:22", &net.TCPAddr{}, key); err != nil {
		t.Fatalf("unknown key should be accepted: %v", err)
	}
	if c.captured() == nil {
		t.Fatal("unknown key should be recorded for capture")
	}
}

func TestCapturingCallbackRejectsMismatch(t *testing.T) {
	c := &capturingCallback{strict: func(string, net.Addr, ssh.PublicKey) error {
		return &knownhosts.KeyError{Want: []knownhosts.KnownKey{{}}} // non-empty => mismatch
	}}
	err := c.callback("h:22", &net.TCPAddr{}, testHostKey(t))
	if err == nil {
		t.Fatal("a key mismatch must stay strict (rejected), not be captured")
	}
	if c.captured() != nil {
		t.Fatal("a mismatched key must NOT be captured")
	}
}

func TestCapturingCallbackPassesThroughKnown(t *testing.T) {
	c := &capturingCallback{strict: func(string, net.Addr, ssh.PublicKey) error {
		return nil // already known/verified
	}}
	if err := c.callback("h:22", &net.TCPAddr{}, testHostKey(t)); err != nil {
		t.Fatalf("known key should verify: %v", err)
	}
	if c.captured() != nil {
		t.Fatal("an already-known key need not be re-captured")
	}
}

// TestDialCaptureSeedsKnownHostsThenStrict is the end-to-end capture path: a
// fresh fleet has an empty known_hosts, the capturing dial learns the peer's
// host key and writes it, and a subsequent strict (non-capture) dial against
// the same file then succeeds with no manual ssh-keyscan.
func TestDialCaptureSeedsKnownHostsThenStrict(t *testing.T) {
	env := setupTestEnv(t)
	srv := newFakeServer(t, env.caPubKey)
	defer srv.Close()

	// known_hosts does not exist yet (fresh fleet).
	if _, err := os.Stat(env.knownHostsPath); !os.IsNotExist(err) {
		t.Fatalf("expected no known_hosts, got %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cl, err := Dial(ctx, srv.addr, Options{
		CertPath:       env.certPath,
		KeyPath:        env.keyPath,
		KnownHostsPath: env.knownHostsPath,
		User:           "root",
		CaptureHostKey: true,
	})
	if err != nil {
		t.Fatalf("capture Dial: %v", err)
	}
	_ = cl.Close()

	b, err := os.ReadFile(env.knownHostsPath)
	if err != nil {
		t.Fatalf("known_hosts not written: %v", err)
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		t.Fatal("known_hosts is empty after capture dial")
	}

	// A strict dial (no capture) now verifies against the seeded file.
	cl2, err := Dial(ctx, srv.addr, Options{
		CertPath:       env.certPath,
		KeyPath:        env.keyPath,
		KnownHostsPath: env.knownHostsPath,
		User:           "root",
	})
	if err != nil {
		t.Fatalf("strict Dial after capture should succeed: %v", err)
	}
	_ = cl2.Close()
}

// TestDialStrictRejectsUnknown confirms that without capture a fresh fleet's
// missing known_hosts still fails strictly (no silent TOFU at push time).
func TestDialStrictRejectsUnknown(t *testing.T) {
	env := setupTestEnv(t)
	srv := newFakeServer(t, env.caPubKey)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := Dial(ctx, srv.addr, Options{
		CertPath:       env.certPath,
		KeyPath:        env.keyPath,
		KnownHostsPath: env.knownHostsPath,
		User:           "root",
	})
	if err == nil {
		t.Fatal("strict dial against missing known_hosts must fail")
	}
}
