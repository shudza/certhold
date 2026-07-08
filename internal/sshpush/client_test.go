package sshpush

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/peerfiles"
)

// fakeSession captures one ssh exec session for assertion.
type fakeSession struct {
	command string
	stdin   []byte
}

// fakeServer is a tiny in-process sshd that accepts a single cert-authenticated
// client, accepts arbitrary "exec" sessions, records the command and stdin,
// echoes nothing, and exits with status 0.
type fakeServer struct {
	listener net.Listener
	addr     string
	hostKey  ssh.Signer
	caPubKey ssh.PublicKey

	mu          sync.Mutex
	sessions    []fakeSession
	stdoutByCmd map[string][]byte
	stopErr     error
	wg          sync.WaitGroup
	execLocal   bool
	activeConns int
}

// runLocalShell executes the session command via the local shell so splice
// semantics (mkdir/touch/sed/append) run against a real filesystem.
func runLocalShell(cmd string, stdin []byte, ch ssh.Channel) uint32 {
	c := exec.Command("sh", "-c", cmd)
	c.Stdin = bytes.NewReader(stdin)
	out, err := c.Output()
	if len(out) > 0 {
		_, _ = ch.Write(out)
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return uint32(ee.ExitCode())
		}
		return 127
	}
	return 0
}

func (s *fakeServer) setStdout(cmd string, out []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stdoutByCmd == nil {
		s.stdoutByCmd = map[string][]byte{}
	}
	s.stdoutByCmd[cmd] = out
}

func (s *fakeServer) stdoutFor(cmd string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stdoutByCmd[cmd]
}

func (s *fakeServer) Sessions() []fakeSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]fakeSession, len(s.sessions))
	copy(out, s.sessions)
	return out
}

func (s *fakeServer) record(sess fakeSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = append(s.sessions, sess)
}

func (s *fakeServer) Close() {
	_ = s.listener.Close()
	s.wg.Wait()
}

func newFakeServer(t *testing.T, caPubKey ssh.PublicKey) *fakeServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeServer{
		listener: ln,
		addr:     ln.Addr().String(),
		hostKey:  hostSigner,
		caPubKey: caPubKey,
	}
	s.wg.Add(1)
	go s.acceptLoop()
	return s
}

func (s *fakeServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

// active reports how many accepted connections are currently being served, so a
// test can observe a client-side Close arriving at the server (no-leak proof).
func (s *fakeServer) active() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeConns
}

func (s *fakeServer) handleConn(nConn net.Conn) {
	defer s.wg.Done()
	defer nConn.Close()
	s.mu.Lock()
	s.activeConns++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.activeConns--
		s.mu.Unlock()
	}()
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), s.caPubKey.Marshal())
		},
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: checker.Authenticate,
	}
	cfg.AddHostKey(s.hostKey)

	_, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		s.mu.Lock()
		s.stopErr = err
		s.mu.Unlock()
		return
	}
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "unknown")
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			continue
		}
		go s.handleSession(ch, requests)
	}
}

func (s *fakeServer) handleSession(ch ssh.Channel, requests <-chan *ssh.Request) {
	var cmd string
	var stdin bytes.Buffer
	stdinDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(&stdin, ch)
		close(stdinDone)
	}()
	for req := range requests {
		switch req.Type {
		case "exec":
			var payload struct{ Command string }
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				_ = req.Reply(false, nil)
				_ = ch.Close()
				return
			}
			cmd = payload.Command
			_ = req.Reply(true, nil)
			if out := s.stdoutFor(cmd); len(out) > 0 {
				_, _ = ch.Write(out)
			}
			<-stdinDone
			status := uint32(0)
			if s.execLocal {
				status = runLocalShell(cmd, stdin.Bytes(), ch)
			}
			s.record(fakeSession{command: cmd, stdin: stdin.Bytes()})
			exitMsg := struct{ Status uint32 }{Status: status}
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(&exitMsg))
			_ = ch.Close()
			return
		default:
			_ = req.Reply(false, nil)
		}
	}
}

// testEnv generates a CA, a peer key+cert, and writes them as files alongside
// a known_hosts file for the fake server.
type testEnv struct {
	certPath       string
	keyPath        string
	knownHostsPath string
	caPubKey       ssh.PublicKey
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()

	caObj, err := ca.Generate(filepath.Join(dir, "ca"))
	if err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	caPubAK := caObj.PublicKeyAuthorizedKey()
	caPub, _, _, _, err := ssh.ParseAuthorizedKey(caPubAK)
	if err != nil {
		t.Fatalf("parse ca pub: %v", err)
	}

	peerPrivPEM, _, peerPub, err := ca.GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey: %v", err)
	}
	keyPath := filepath.Join(dir, "peer_key")
	if err := os.WriteFile(keyPath, peerPrivPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	certBytes, _, err := caObj.SignCert(ca.SignOptions{
		Pubkey:     peerPub,
		KeyID:      "test-certhold",
		Principals: []string{"root", "manager", "certhold"},
	})
	if err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	certPath := filepath.Join(dir, "peer-cert.pub")
	if err := os.WriteFile(certPath, certBytes, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	// known_hosts is populated later, after fake server is created and we know
	// its host key + addr. Return placeholder path.
	knownHostsPath := filepath.Join(dir, "known_hosts")

	return &testEnv{
		certPath:       certPath,
		keyPath:        keyPath,
		knownHostsPath: knownHostsPath,
		caPubKey:       caPub,
	}
}

// writeKnownHosts writes a known_hosts entry for the given addr and host key.
func (e *testEnv) writeKnownHosts(t *testing.T, addr string, hostKey ssh.PublicKey) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	target := host
	if port != "22" {
		target = fmt.Sprintf("[%s]:%s", host, port)
	}
	pubBytes := ssh.MarshalAuthorizedKey(hostKey)
	line := fmt.Sprintf("%s %s", target, strings.TrimSpace(string(pubBytes)))
	if err := os.WriteFile(e.knownHostsPath, []byte(line+"\n"), 0644); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
}

// pemSanity ensures the test env's key file is parseable as PEM (sanity check
// that should always pass with our ca package).
func pemSanity(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if block, _ := pem.Decode(b); block == nil {
		t.Fatalf("file %s does not decode as PEM", path)
	}
}

func dialClient(t *testing.T, env *testEnv, srv *fakeServer) *Client {
	t.Helper()
	env.writeKnownHosts(t, srv.addr, srv.hostKey.PublicKey())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cl, err := Dial(ctx, srv.addr, Options{
		CertPath:       env.certPath,
		KeyPath:        env.keyPath,
		KnownHostsPath: env.knownHostsPath,
		User:           "root",
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	return cl
}

func TestDialLoadsCertAndKey(t *testing.T) {
	env := setupTestEnv(t)
	pemSanity(t, env.keyPath)
	srv := newFakeServer(t, env.caPubKey)
	defer srv.Close()
	cl := dialClient(t, env, srv)
	if err := cl.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestWriteFileAtomic(t *testing.T) {
	env := setupTestEnv(t)
	srv := newFakeServer(t, env.caPubKey)
	defer srv.Close()
	cl := dialClient(t, env, srv)
	defer cl.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	content := []byte("hello\nworld\n")
	if err := cl.WriteFileAtomic(ctx, "/tmp/foo", content, 0644); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}
	sessions := srv.Sessions()
	if len(sessions) != 2 {
		t.Fatalf("got %d sessions, want 2: %+v", len(sessions), sessions)
	}
	if !strings.Contains(sessions[0].command, "cat > '/tmp/foo.staging'") {
		t.Errorf("first command does not contain `cat > '/tmp/foo.staging'`: %q", sessions[0].command)
	}
	if !strings.Contains(sessions[0].command, "chmod 644 '/tmp/foo.staging'") {
		t.Errorf("first command does not contain `chmod 644 '/tmp/foo.staging'`: %q", sessions[0].command)
	}
	if !bytes.Equal(sessions[0].stdin, content) {
		t.Errorf("stdin mismatch: got %q want %q", sessions[0].stdin, content)
	}
	wantMove := "mv -f '/tmp/foo.staging' '/tmp/foo'"
	if sessions[1].command != wantMove {
		t.Errorf("second command = %q, want %q", sessions[1].command, wantMove)
	}
}

func TestReloadSSHD(t *testing.T) {
	env := setupTestEnv(t)
	srv := newFakeServer(t, env.caPubKey)
	defer srv.Close()
	cl := dialClient(t, env, srv)
	defer cl.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := cl.ReloadSSHD(ctx); err != nil {
		t.Fatalf("ReloadSSHD: %v", err)
	}
	sessions := srv.Sessions()
	if len(sessions) != 1 {
		t.Fatalf("got %d sessions, want 1", len(sessions))
	}
	if sessions[0].command != "systemctl reload sshd" {
		t.Errorf("command = %q, want %q", sessions[0].command, "systemctl reload sshd")
	}
}

func TestVerifyHealth(t *testing.T) {
	env := setupTestEnv(t)
	srv := newFakeServer(t, env.caPubKey)
	defer srv.Close()
	cl := dialClient(t, env, srv)
	defer cl.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := cl.VerifyHealth(ctx); err != nil {
		t.Fatalf("VerifyHealth: %v", err)
	}
	sessions := srv.Sessions()
	if len(sessions) != 1 {
		t.Fatalf("got %d sessions, want 1", len(sessions))
	}
	if sessions[0].command != "true" {
		t.Errorf("command = %q, want %q", sessions[0].command, "true")
	}
}

func TestReadFile(t *testing.T) {
	env := setupTestEnv(t)
	srv := newFakeServer(t, env.caPubKey)
	defer srv.Close()
	cl := dialClient(t, env, srv)
	defer cl.Close()

	const want = "hello from cat\n"
	srv.setStdout("cat '/etc/foo'", []byte(want))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := cl.ReadFile(ctx, "/etc/foo")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestCloseIdempotent(t *testing.T) {
	env := setupTestEnv(t)
	srv := newFakeServer(t, env.caPubKey)
	defer srv.Close()
	cl := dialClient(t, env, srv)
	if err := cl.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := cl.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := cl.VerifyHealth(ctx)
	if err == nil {
		t.Fatal("VerifyHealth on closed client: want error, got nil")
	}
}

func TestDefaultPortAndUser(t *testing.T) {
	// Drives the host-has-no-port branch of Dial. Since 127.0.0.1 (no port)
	// would dial real port 22, we just unit-test the helper. Wrap Dial with a
	// host that has no colon -> expect dial to fail with connection refused
	// (or context deadline) and the error message to include ":22".
	env := setupTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	// fake known_hosts so the file load itself doesn't fail.
	if err := os.WriteFile(env.knownHostsPath, []byte{}, 0644); err != nil {
		t.Fatalf("write empty known_hosts: %v", err)
	}
	_, err := Dial(ctx, "127.0.0.1", Options{
		CertPath:       env.certPath,
		KeyPath:        env.keyPath,
		KnownHostsPath: env.knownHostsPath,
		User:           "",
	})
	if err == nil {
		t.Fatal("Dial: want error (no real sshd on :22), got nil")
	}
	if !strings.Contains(err.Error(), "127.0.0.1:22") {
		t.Errorf("error should mention 127.0.0.1:22, got: %v", err)
	}
}

func TestDialBadCertFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	certPath := filepath.Join(dir, "cert.pub")
	kh := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(kh, []byte{}, 0644); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	// valid key
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "test")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	// cert path that is actually a plain public key, not a cert
	pub, err := ssh.NewPublicKey(priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("new pub: %v", err)
	}
	if err := os.WriteFile(certPath, ssh.MarshalAuthorizedKey(pub), 0644); err != nil {
		t.Fatalf("write fake cert: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = Dial(ctx, "127.0.0.1:0", Options{
		CertPath:       certPath,
		KeyPath:        keyPath,
		KnownHostsPath: kh,
	})
	if err == nil {
		t.Fatal("Dial: want error for non-cert file, got nil")
	}
	if !strings.Contains(err.Error(), "ssh certificate") {
		t.Errorf("error = %v, want mention of 'ssh certificate'", err)
	}
}

func TestDialMissingKeyFile(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := Dial(ctx, "127.0.0.1:0", Options{
		CertPath:       filepath.Join(dir, "missing-cert"),
		KeyPath:        filepath.Join(dir, "missing-key"),
		KnownHostsPath: filepath.Join(dir, "missing-kh"),
	})
	if err == nil {
		t.Fatal("Dial: want error for missing key, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error = %v, want os.ErrNotExist", err)
	}
}

func TestDialEncryptedKeyWithPassphrase(t *testing.T) {
	dir := t.TempDir()
	caObj, err := ca.Generate(filepath.Join(dir, "ca"))
	if err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	caPubAK := caObj.PublicKeyAuthorizedKey()
	caPub, _, _, _, err := ssh.ParseAuthorizedKey(caPubAK)
	if err != nil {
		t.Fatalf("parse ca pub: %v", err)
	}

	const pass = "keypw"
	peerPrivPEM, _, peerPub, err := ca.GeneratePeerKeyWithPassphrase([]byte(pass))
	if err != nil {
		t.Fatalf("GeneratePeerKeyWithPassphrase: %v", err)
	}
	keyPath := filepath.Join(dir, "peer_key")
	if err := os.WriteFile(keyPath, peerPrivPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	certBytes, _, err := caObj.SignCert(ca.SignOptions{Pubkey: peerPub, KeyID: "t", Principals: []string{"root", "manager"}})
	if err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	certPath := filepath.Join(dir, "peer-cert.pub")
	if err := os.WriteFile(certPath, certBytes, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	khPath := filepath.Join(dir, "known_hosts")

	srv := newFakeServer(t, caPub)
	defer srv.Close()

	host, port, _ := net.SplitHostPort(srv.addr)
	target := host
	if port != "22" {
		target = fmt.Sprintf("[%s]:%s", host, port)
	}
	hkLine := fmt.Sprintf("%s %s\n", target, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(srv.hostKey.PublicKey()))))
	if err := os.WriteFile(khPath, []byte(hkLine), 0644); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	called := false
	cl, err := Dial(ctx, srv.addr, Options{
		CertPath:       certPath,
		KeyPath:        keyPath,
		KnownHostsPath: khPath,
		User:           "root",
		PassphraseFn: func() ([]byte, error) {
			called = true
			return []byte(pass), nil
		},
	})
	if err != nil {
		t.Fatalf("Dial with encrypted key: %v", err)
	}
	defer cl.Close()
	if !called {
		t.Error("PassphraseFn was not invoked for an encrypted key")
	}
}

func TestDialEncryptedKeyNilPassphraseFn(t *testing.T) {
	dir := t.TempDir()
	peerPrivPEM, _, _, err := ca.GeneratePeerKeyWithPassphrase([]byte("pw"))
	if err != nil {
		t.Fatalf("GeneratePeerKeyWithPassphrase: %v", err)
	}
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, peerPrivPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	certPath := filepath.Join(dir, "cert.pub")
	if err := os.WriteFile(certPath, []byte("unused"), 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	khPath := filepath.Join(dir, "kh")
	if err := os.WriteFile(khPath, []byte{}, 0644); err != nil {
		t.Fatalf("write kh: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = Dial(ctx, "127.0.0.1:0", Options{
		CertPath:       certPath,
		KeyPath:        keyPath,
		KnownHostsPath: khPath,
	})
	if err == nil {
		t.Fatal("Dial with encrypted key and nil PassphraseFn: want error, got nil")
	}
	if !strings.Contains(err.Error(), "passphrase-protected") {
		t.Errorf("error = %v, want mention of 'passphrase-protected'", err)
	}
}

func TestEffectiveConnectTimeout(t *testing.T) {
	if got := effectiveConnectTimeout(Options{}); got != defaultConnectTimeout {
		t.Errorf("zero ConnectTimeout: got %v, want %v", got, defaultConnectTimeout)
	}
	if got := effectiveConnectTimeout(Options{ConnectTimeout: 3 * time.Second}); got != 3*time.Second {
		t.Errorf("explicit ConnectTimeout: got %v, want %v", got, 3*time.Second)
	}
}

// TestDialFailsFastUnreachable verifies that with a deadline-less context and a
// small ConnectTimeout, Dial against a black-hole address (TEST-NET-1, packets
// dropped) returns an error well before the multi-minute OS TCP timeout.
func TestDialFailsFastUnreachable(t *testing.T) {
	env := setupTestEnv(t)
	if err := os.WriteFile(env.knownHostsPath, []byte{}, 0644); err != nil {
		t.Fatalf("write empty known_hosts: %v", err)
	}
	start := time.Now()
	_, err := Dial(context.Background(), "192.0.2.1:22", Options{
		CertPath:       env.certPath,
		KeyPath:        env.keyPath,
		KnownHostsPath: env.knownHostsPath,
		User:           "root",
		ConnectTimeout: 1 * time.Second,
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Dial to black-hole address: want error, got nil")
	}
	if elapsed >= 5*time.Second {
		t.Fatalf("Dial took %v, want fail-fast under 5s (OS default not bounded)", elapsed)
	}
	t.Logf("fail-fast: Dial returned %v after %v", err, elapsed)
}

// TestDialTimesOutOnStalledHandshake proves the pausable connect timer still
// fully bounds TCP connect + handshake when no host-key confirmation is
// pending: a server that accepts and then stalls (never speaks SSH) fails the
// dial at ~ConnectTimeout with a deadline error, not the OS-level default.
func TestDialTimesOutOnStalledHandshake(t *testing.T) {
	env := setupTestEnv(t)
	if err := os.WriteFile(env.knownHostsPath, []byte{}, 0644); err != nil {
		t.Fatalf("write empty known_hosts: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	// Closing the stalled conns at cleanup unblocks the abandoned handshake
	// goroutine (and its drain) so the test process exits promptly.
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
	})

	start := time.Now()
	_, err = Dial(context.Background(), ln.Addr().String(), Options{
		CertPath:       env.certPath,
		KeyPath:        env.keyPath,
		KnownHostsPath: env.knownHostsPath,
		User:           "root",
		ConnectTimeout: 1 * time.Second,
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Dial against a stalled server: want error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Dial error = %v, want context.DeadlineExceeded", err)
	}
	// Generous upper bound for slow CI; the point is ~1s, not minutes.
	if elapsed >= 10*time.Second {
		t.Fatalf("Dial took %v, want ~1s fail-fast", elapsed)
	}
	t.Logf("stalled handshake: Dial returned %v after %v", err, elapsed)
}

var _ Pusher = (*Client)(nil)

func dialExecLocalClient(t *testing.T) *Client {
	t.Helper()
	cl, _ := dialExecLocalClientEnv(t)
	return cl
}

// dialExecLocalClientEnv is dialExecLocalClient but also returns the test env so
// callers that need the CA public key (e.g. ClearPeer) can reach it.
func dialExecLocalClientEnv(t *testing.T) (*Client, *testEnv) {
	t.Helper()
	env := setupTestEnv(t)
	srv := newFakeServer(t, env.caPubKey)
	srv.execLocal = true
	t.Cleanup(srv.Close)
	cl := dialClient(t, env, srv)
	t.Cleanup(func() { _ = cl.Close() })
	return cl, env
}

func TestSpliceConfigBlock_FreshFile(t *testing.T) {
	cl := dialExecLocalClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := filepath.Join(t.TempDir(), "home", ".ssh", "config")
	block := peerfiles.V2SshClientBlockWithHosts("k1", []peerfiles.HostEntry{{Name: "web01", Address: "10.0.0.5", User: "deploy"}})
	if err := cl.SpliceConfigBlock(ctx, cfg, "k1", block); err != nil {
		t.Fatalf("SpliceConfigBlock: %v", err)
	}
	got, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(got) != block {
		t.Errorf("fresh config = %q, want exactly the block %q", got, block)
	}
	fi, err := os.Stat(cfg)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("created config mode = %o, want 0600", fi.Mode().Perm())
	}
}

func TestSpliceConfigBlock_PreservesUserContentAndForeignBlock(t *testing.T) {
	cl := dialExecLocalClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	userContent := "Host personal\n    HostName example.com\n"
	foreign := peerfiles.V2SshClientBlockWithHosts("otherkey", nil)
	staleVersionless := "# BEGIN certhold k1\nstale line\n# END certhold k1\n"
	if err := os.WriteFile(cfg, []byte(userContent+foreign+staleVersionless), 0644); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	block := peerfiles.V2SshClientBlockWithHosts("k1", []peerfiles.HostEntry{{Name: "db01", Address: "10.0.0.7", User: "root"}})
	if err := cl.SpliceConfigBlock(ctx, cfg, "k1", block); err != nil {
		t.Fatalf("SpliceConfigBlock: %v", err)
	}
	got, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	want := userContent + foreign + block
	if string(got) != want {
		t.Errorf("config after splice = %q, want %q", got, want)
	}
	if strings.Contains(string(got), "stale line") {
		t.Errorf("stale versionless block survived the splice: %q", got)
	}
}

func TestSpliceConfigBlock_Idempotent(t *testing.T) {
	cl := dialExecLocalClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := filepath.Join(t.TempDir(), "config")
	block := peerfiles.V2SshClientBlockWithHosts("k1", []peerfiles.HostEntry{{Name: "web01", Address: "10.0.0.5", User: "deploy"}})
	for i := 0; i < 2; i++ {
		if err := cl.SpliceConfigBlock(ctx, cfg, "k1", block); err != nil {
			t.Fatalf("SpliceConfigBlock #%d: %v", i+1, err)
		}
	}
	got, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(got) != block {
		t.Errorf("re-splice not idempotent: got %q, want %q", got, block)
	}
	if n := strings.Count(string(got), "# BEGIN certhold k1"); n != 1 {
		t.Errorf("begin sentinel appears %d times, want 1", n)
	}
}

// clearPaths builds RemotePaths rooted at a temp .ssh dir and writes the
// identity files, config, and authorized_keys an install would leave behind.
func clearPaths(t *testing.T, env *testEnv, key string) peerfiles.RemotePaths {
	t.Helper()
	sshDir := filepath.Join(t.TempDir(), ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	paths := peerfiles.RemotePaths{
		Cert:           filepath.Join(sshDir, peerfiles.V2CertFileName(key)),
		AuthorizedKeys: filepath.Join(sshDir, "authorized_keys"),
		ConfigTarget:   filepath.Join(sshDir, "config"),
	}
	keyPath := filepath.Join(sshDir, peerfiles.V2KeyFileName(key))
	if err := os.WriteFile(keyPath, []byte("PRIVATE"), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.WriteFile(paths.Cert, []byte("CERT"), 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	return paths
}

func TestClearPeer_RemovesEverything(t *testing.T) {
	cl, env := dialExecLocalClientEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const key = "k1"
	paths := clearPaths(t, env, key)
	userCfg := "Host personal\n    HostName example.com\n"
	foreign := peerfiles.V2SshClientBlock("otherkey")
	if err := os.WriteFile(paths.ConfigTarget, []byte(userCfg+peerfiles.V2SshClientBlock(key)+foreign), 0600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	caTrim := strings.TrimRight(string(ssh.MarshalAuthorizedKey(env.caPubKey)), "\n")
	ak := "ssh-ed25519 AAAAuser u@h\ncert-authority,principals=\"manager,web\" " + caTrim + "\n"
	if err := os.WriteFile(paths.AuthorizedKeys, []byte(ak), 0600); err != nil {
		t.Fatalf("seed authorized_keys: %v", err)
	}

	if err := cl.ClearPeer(ctx, paths, key, env.caPubKey); err != nil {
		t.Fatalf("ClearPeer: %v", err)
	}

	gotCfg, err := os.ReadFile(paths.ConfigTarget)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if strings.Contains(string(gotCfg), peerfiles.BeginSentinel(key)) {
		t.Errorf("own config block survived:\n%s", gotCfg)
	}
	if !strings.Contains(string(gotCfg), peerfiles.BeginSentinel("otherkey")) {
		t.Errorf("foreign config block was removed:\n%s", gotCfg)
	}
	if !strings.Contains(string(gotCfg), "Host personal") {
		t.Errorf("user config dropped:\n%s", gotCfg)
	}

	gotAK, err := os.ReadFile(paths.AuthorizedKeys)
	if err != nil {
		t.Fatalf("read authorized_keys: %v", err)
	}
	if strings.Contains(string(gotAK), caTrim) {
		t.Errorf("cert-authority line survived:\n%s", gotAK)
	}
	if !strings.Contains(string(gotAK), "ssh-ed25519 AAAAuser u@h") {
		t.Errorf("user authorized_keys line dropped:\n%s", gotAK)
	}

	if _, err := os.Stat(paths.Cert); !os.IsNotExist(err) {
		t.Errorf("cert file not removed: %v", err)
	}
	keyPath := filepath.Join(filepath.Dir(paths.ConfigTarget), peerfiles.V2KeyFileName(key))
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Errorf("private key not removed: %v", err)
	}
}

func TestClearPeer_IdempotentAndMissingFilesOK(t *testing.T) {
	cl, env := dialExecLocalClientEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const key = "k1"
	sshDir := filepath.Join(t.TempDir(), ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	paths := peerfiles.RemotePaths{
		Cert:           filepath.Join(sshDir, peerfiles.V2CertFileName(key)),
		AuthorizedKeys: filepath.Join(sshDir, "authorized_keys"),
		ConfigTarget:   filepath.Join(sshDir, "config"),
	}

	for i := 0; i < 2; i++ {
		if err := cl.ClearPeer(ctx, paths, key, env.caPubKey); err != nil {
			t.Fatalf("ClearPeer on missing files #%d returned error: %v", i+1, err)
		}
	}
}
