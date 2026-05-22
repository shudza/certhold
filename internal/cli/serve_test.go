package cli

import (
	"bytes"
	"context"
	"path/filepath"
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
		"--hostname", "test",
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- cmd.ExecuteContext(ctx)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if bytes.Contains([]byte(out.String()), []byte("listening on")) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !bytes.Contains([]byte(out.String()), []byte("listening on")) {
		cancel()
		<-done
		t.Fatalf("server never printed listening line; out=%q errBuf=%q", out.String(), errBuf.String())
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
