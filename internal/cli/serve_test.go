package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
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
