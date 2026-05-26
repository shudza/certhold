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
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
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

func (s *fakeServer) handleConn(nConn net.Conn) {
	defer s.wg.Done()
	defer nConn.Close()
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
			s.record(fakeSession{command: cmd, stdin: stdin.Bytes()})
			exitMsg := struct{ Status uint32 }{Status: 0}
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

var _ Pusher = (*Client)(nil)
