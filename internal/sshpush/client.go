// Package sshpush pushes peer config changes over SSH using certhold's own peer cert.
//
// Certhold has no bespoke transport: every state change is delivered by
// SSHing into the target peer with certhold's CA-signed cert, writing files
// to a staging path, atomically renaming them into place, then reloading
// sshd. Client wraps a single live ssh.Client and exposes the operations
// needed by higher-level orchestration (T10–T13).
package sshpush

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/shudza/certhold/internal/passphrase"
)

const defaultConnectTimeout = 15 * time.Second

type Options struct {
	CertPath       string
	KeyPath        string
	KnownHostsPath string
	User           string
	// PassphraseFn supplies the passphrase for an encrypted key. It is only
	// invoked when the key file turns out to be encrypted; plaintext keys never
	// call it, so callers with plaintext keys may leave it nil.
	PassphraseFn func() ([]byte, error)
	// CaptureHostKey enables enroll-time host-key capture: a presented key that
	// is *unknown* (no known_hosts entry yet) is accepted and recorded into the
	// known_hosts file at dial time, while a *mismatch* against an existing
	// entry still fails strictly. Leave false for ordinary pushes, which must
	// stay strict and never learn a new key.
	CaptureHostKey bool
	// ConnectTimeout bounds TCP connect + SSH handshake for a single dial. Zero means use the package default.
	ConnectTimeout time.Duration
}

// effectiveConnectTimeout returns opts.ConnectTimeout when positive, else the
// package default.
func effectiveConnectTimeout(opts Options) time.Duration {
	if opts.ConnectTimeout > 0 {
		return opts.ConnectTimeout
	}
	return defaultConnectTimeout
}

type Client struct {
	mu     sync.Mutex
	client *ssh.Client
	closed bool
}

func Dial(ctx context.Context, host string, opts Options) (*Client, error) {
	keyBytes, err := os.ReadFile(opts.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", opts.KeyPath, err)
	}
	rawKey, err := ssh.ParseRawPrivateKey(keyBytes)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if !errors.As(err, &missing) {
			return nil, fmt.Errorf("parse private key %s: %w", opts.KeyPath, err)
		}
		if opts.PassphraseFn == nil {
			return nil, fmt.Errorf("key %s is passphrase-protected but no passphrase source was provided", opts.KeyPath)
		}
		pass, perr := opts.PassphraseFn()
		if perr != nil {
			return nil, fmt.Errorf("obtain key passphrase for %s: %w", opts.KeyPath, perr)
		}
		rawKey, err = ssh.ParseRawPrivateKeyWithPassphrase(keyBytes, pass)
		passphrase.Zero(pass)
		if err != nil {
			return nil, fmt.Errorf("parse encrypted private key %s: %w", opts.KeyPath, err)
		}
	}
	signer, err := ssh.NewSignerFromKey(rawKey)
	if err != nil {
		return nil, fmt.Errorf("new signer: %w", err)
	}
	certBytes, err := os.ReadFile(opts.CertPath)
	if err != nil {
		return nil, fmt.Errorf("read cert %s: %w", opts.CertPath, err)
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert %s: %w", opts.CertPath, err)
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("file %s does not contain an ssh certificate (got %T)", opts.CertPath, pk)
	}
	certSigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		return nil, fmt.Errorf("new cert signer: %w", err)
	}
	hkCallback, err := loadHostKeyCallback(opts.KnownHostsPath, opts.CaptureHostKey)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts %s: %w", opts.KnownHostsPath, err)
	}
	var capturer *capturingCallback
	if opts.CaptureHostKey {
		capturer = &capturingCallback{strict: hkCallback}
		hkCallback = capturer.callback
	}
	user := opts.User
	if user == "" {
		user = "root"
	}
	addr := host
	if !strings.Contains(addr, ":") {
		addr += ":22"
	}
	to := effectiveConnectTimeout(opts)
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback: hkCallback,
		Timeout:         to,
	}
	dctx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		dctx, cancel = context.WithTimeout(ctx, to)
		defer cancel()
	}
	dialer := &dialFn{ctx: dctx, addr: addr, cfg: cfg}
	sshClient, err := dialer.dial()
	if err != nil {
		return nil, fmt.Errorf("ssh dial %s: %w", addr, err)
	}
	// On a capturing dial, persist any newly learned host key keyed by the dial
	// address so subsequent strict pushes verify against it. A write failure is
	// non-fatal: the connection is already up and the caller (enroll probe) can
	// still record reachability; the next push just re-captures.
	if capturer != nil {
		if key := capturer.captured(); key != nil {
			_ = AppendKnownHost(opts.KnownHostsPath, addr, key)
		}
	}
	return &Client{client: sshClient}, nil
}

// loadHostKeyCallback builds the strict knownhosts callback. When capture is
// requested the known_hosts file may not exist yet on a fresh fleet; in that
// case an empty callback (reject-everything-as-unknown) is returned so the
// capturing wrapper can learn the first key. For ordinary (non-capture) dials a
// missing file is a real error: pushes must verify against a seeded file.
func loadHostKeyCallback(path string, capture bool) (ssh.HostKeyCallback, error) {
	cb, err := knownhosts.New(path)
	if err == nil {
		return cb, nil
	}
	if capture && errors.Is(err, fs.ErrNotExist) {
		return func(string, net.Addr, ssh.PublicKey) error {
			return &knownhosts.KeyError{}
		}, nil
	}
	return nil, err
}

type dialFn struct {
	ctx  context.Context
	addr string
	cfg  *ssh.ClientConfig
}

func (d *dialFn) dial() (*ssh.Client, error) {
	type result struct {
		c   *ssh.Client
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ssh.Dial("tcp", d.addr, d.cfg)
		ch <- result{c, err}
	}()
	select {
	case <-d.ctx.Done():
		return nil, d.ctx.Err()
	case r := <-ch:
		return r.c, r.err
	}
}

func (c *Client) WriteFileAtomic(ctx context.Context, remotePath string, content []byte, mode fs.FileMode) error {
	c.mu.Lock()
	cl := c.client
	c.mu.Unlock()
	if cl == nil {
		return errors.New("sshpush: client is closed")
	}
	staging := remotePath + ".staging"
	octMode := fmt.Sprintf("%o", mode.Perm())
	writeCmd := fmt.Sprintf("cat > %s && chmod %s %s", shellQuote(staging), octMode, shellQuote(staging))
	if err := runWithStdin(ctx, cl, writeCmd, content); err != nil {
		_ = bestEffortRemove(cl, staging)
		return fmt.Errorf("write staging %s: %w", staging, err)
	}
	moveCmd := fmt.Sprintf("mv -f %s %s", shellQuote(staging), shellQuote(remotePath))
	if err := runSimple(ctx, cl, moveCmd); err != nil {
		_ = bestEffortRemove(cl, staging)
		return fmt.Errorf("rename staging %s -> %s: %w", staging, remotePath, err)
	}
	return nil
}

func (c *Client) ReadFile(ctx context.Context, remotePath string) ([]byte, error) {
	c.mu.Lock()
	cl := c.client
	c.mu.Unlock()
	if cl == nil {
		return nil, errors.New("sshpush: client is closed")
	}
	cmd := fmt.Sprintf("cat %s", shellQuote(remotePath))
	return runCapture(ctx, cl, cmd)
}

// SpliceConfigBlock is the remote equivalent of the install-script splice: it
// ensures the config file exists (0600 on create), removes this instance's
// sentinel range with a version-agnostic sed, then appends the new block.
// Foreign instances' blocks and user content are left untouched.
func (c *Client) SpliceConfigBlock(ctx context.Context, configPath string, instanceKey string, block string) error {
	c.mu.Lock()
	cl := c.client
	c.mu.Unlock()
	if cl == nil {
		return errors.New("sshpush: client is closed")
	}
	q := shellQuote(configPath)
	prepCmd := fmt.Sprintf("mkdir -p %s && if [ ! -e %s ]; then touch %s && chmod 600 %s; fi",
		shellQuote(path.Dir(configPath)), q, q, q)
	if err := runSimple(ctx, cl, prepCmd); err != nil {
		return fmt.Errorf("prepare config %s: %w", configPath, err)
	}
	sedExpr := fmt.Sprintf(`/^# BEGIN certhold %s( v[0-9]+)?$/,/^# END certhold %s( v[0-9]+)?$/d`, instanceKey, instanceKey)
	delCmd := fmt.Sprintf("sed -i -E %s %s", shellQuote(sedExpr), q)
	if err := runSimple(ctx, cl, delCmd); err != nil {
		return fmt.Errorf("delete config block %s: %w", configPath, err)
	}
	appendCmd := fmt.Sprintf("cat >> %s", q)
	if err := runWithStdin(ctx, cl, appendCmd, []byte(block)); err != nil {
		return fmt.Errorf("append config block %s: %w", configPath, err)
	}
	return nil
}

func (c *Client) ReloadSSHD(ctx context.Context) error {
	c.mu.Lock()
	cl := c.client
	c.mu.Unlock()
	if cl == nil {
		return errors.New("sshpush: client is closed")
	}
	return runSimple(ctx, cl, "systemctl reload sshd")
}

func (c *Client) VerifyHealth(ctx context.Context) error {
	c.mu.Lock()
	cl := c.client
	c.mu.Unlock()
	if cl == nil {
		return errors.New("sshpush: client is closed")
	}
	return runSimple(ctx, cl, "true")
}

func (c *Client) Close() error {
	// Defensive: a failed Dial can surface a nil *Client through the Pusher
	// interface (typed nil), and callers may still call Close on it.
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.client == nil {
		c.closed = true
		return nil
	}
	c.closed = true
	cl := c.client
	c.client = nil
	return cl.Close()
}

func runSimple(ctx context.Context, cl *ssh.Client, cmd string) error {
	sess, err := cl.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		return ctx.Err()
	case err := <-done:
		if err != nil {
			return fmt.Errorf("run %q: %w", cmd, err)
		}
		return nil
	}
}

func runWithStdin(ctx context.Context, cl *ssh.Client, cmd string, stdin []byte) error {
	sess, err := cl.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()
	stdinPipe, err := sess.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	if err := sess.Start(cmd); err != nil {
		return fmt.Errorf("start %q: %w", cmd, err)
	}
	writeErr := make(chan error, 1)
	go func() {
		_, err := io.Copy(stdinPipe, bytes.NewReader(stdin))
		closeErr := stdinPipe.Close()
		if err != nil {
			writeErr <- err
			return
		}
		writeErr <- closeErr
	}()
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		return ctx.Err()
	case err := <-done:
		<-writeErr
		if err != nil {
			return fmt.Errorf("run %q: %w", cmd, err)
		}
		return nil
	}
}

func runCapture(ctx context.Context, cl *ssh.Client, cmd string) ([]byte, error) {
	sess, err := cl.NewSession()
	if err != nil {
		return nil, fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()
	var stdout bytes.Buffer
	sess.Stdout = &stdout
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		return nil, ctx.Err()
	case err := <-done:
		if err != nil {
			return nil, fmt.Errorf("run %q: %w", cmd, err)
		}
		return stdout.Bytes(), nil
	}
}

func bestEffortRemove(cl *ssh.Client, path string) error {
	sess, err := cl.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	return sess.Run(fmt.Sprintf("rm -f %s", shellQuote(path)))
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
