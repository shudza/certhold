package sshpush

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// dialConfirm dials srv with the given HostKeyConfirmFn and no pre-seeded
// known_hosts entry (so the server's key is UNKNOWN at dial time). The
// known_hosts file path exists but is empty, exercising the unknown-host branch.
func dialConfirm(t *testing.T, env *testEnv, srv *fakeServer, confirm func(string, ssh.PublicKey) (bool, error)) (*Client, error) {
	t.Helper()
	if err := os.WriteFile(env.knownHostsPath, []byte{}, 0644); err != nil {
		t.Fatalf("write empty known_hosts: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return Dial(ctx, srv.addr, Options{
		CertPath:         env.certPath,
		KeyPath:          env.keyPath,
		KnownHostsPath:   env.knownHostsPath,
		User:             "root",
		HostKeyConfirmFn: confirm,
	})
}

func TestHostKeyConfirmAcceptsAndPersistsUnknownHost(t *testing.T) {
	env := setupTestEnv(t)
	srv := newFakeServer(t, env.caPubKey)
	defer srv.Close()

	var calls int
	cl, err := dialConfirm(t, env, srv, func(host string, key ssh.PublicKey) (bool, error) {
		calls++
		return true, nil
	})
	if err != nil {
		t.Fatalf("Dial with confirm->true on unknown host: %v", err)
	}
	defer cl.Close()
	if calls != 1 {
		t.Fatalf("confirm fn called %d times, want 1", calls)
	}

	// The accepted key must have been persisted via AppendKnownHost: a second
	// STRICT dial (no confirm, no capture) against the now-seeded file succeeds.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cl2, err := Dial(ctx, srv.addr, Options{
		CertPath:       env.certPath,
		KeyPath:        env.keyPath,
		KnownHostsPath: env.knownHostsPath,
		User:           "root",
	})
	if err != nil {
		t.Fatalf("strict dial after learn: key was not persisted: %v", err)
	}
	cl2.Close()
}

func TestHostKeyConfirmRejectsUnknownHost(t *testing.T) {
	env := setupTestEnv(t)
	srv := newFakeServer(t, env.caPubKey)
	defer srv.Close()

	_, err := dialConfirm(t, env, srv, func(host string, key ssh.PublicKey) (bool, error) {
		return false, nil
	})
	if err == nil {
		t.Fatal("Dial with confirm->false on unknown host: want error, got nil")
	}

	// Nothing must have been persisted: the file is still empty, so a strict
	// dial still fails as unknown.
	got, rerr := os.ReadFile(env.knownHostsPath)
	if rerr != nil {
		t.Fatalf("read known_hosts: %v", rerr)
	}
	if strings.TrimSpace(string(got)) != "" {
		t.Fatalf("rejected key must not be persisted, known_hosts = %q", got)
	}
}

func TestHostKeyConfirmErrorAbortsDial(t *testing.T) {
	env := setupTestEnv(t)
	srv := newFakeServer(t, env.caPubKey)
	defer srv.Close()

	sentinel := errors.New("operator declined")
	_, err := dialConfirm(t, env, srv, func(host string, key ssh.PublicKey) (bool, error) {
		return false, sentinel
	})
	if err == nil {
		t.Fatal("Dial with confirm error: want error, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("Dial error = %v, want it to wrap %v", err, sentinel)
	}
}

func TestHostKeyConfirmNeverCalledOnMismatch(t *testing.T) {
	env := setupTestEnv(t)
	srv := newFakeServer(t, env.caPubKey)
	defer srv.Close()

	// Seed a known_hosts entry for srv's addr with a DIFFERENT (bogus) host key,
	// so the real key presented at dial is a MISMATCH (len(Want) > 0).
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen other key: %v", err)
	}
	otherSigner, err := ssh.NewSignerFromKey(otherPriv)
	if err != nil {
		t.Fatalf("other signer: %v", err)
	}
	env.writeKnownHosts(t, srv.addr, otherSigner.PublicKey())

	var calls int
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = Dial(ctx, srv.addr, Options{
		CertPath:       env.certPath,
		KeyPath:        env.keyPath,
		KnownHostsPath: env.knownHostsPath,
		User:           "root",
		HostKeyConfirmFn: func(host string, key ssh.PublicKey) (bool, error) {
			calls++
			return true, nil
		},
	})
	if err == nil {
		t.Fatal("Dial against a mismatched known_hosts entry: want error, got nil")
	}
	if calls != 0 {
		t.Fatalf("confirm fn must NEVER be called on a mismatch, got %d calls", calls)
	}
}

func TestHostKeyConfirmNotCalledOnKnownMatchingHost(t *testing.T) {
	env := setupTestEnv(t)
	srv := newFakeServer(t, env.caPubKey)
	defer srv.Close()

	// Seed the correct host key so the presented key is KNOWN and matches.
	env.writeKnownHosts(t, srv.addr, srv.hostKey.PublicKey())

	var calls int
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cl, err := Dial(ctx, srv.addr, Options{
		CertPath:       env.certPath,
		KeyPath:        env.keyPath,
		KnownHostsPath: env.knownHostsPath,
		User:           "root",
		HostKeyConfirmFn: func(host string, key ssh.PublicKey) (bool, error) {
			calls++
			return true, nil
		},
	})
	if err != nil {
		t.Fatalf("Dial against a known matching host: %v", err)
	}
	defer cl.Close()
	if calls != 0 {
		t.Fatalf("confirm fn must not be called for a known matching host, got %d calls", calls)
	}
}
