package cli

import (
	"bytes"
	"testing"

	"github.com/shudza/certhold/internal/passphrase"
)

func TestMemoUnlockerGetReturnsFreshCopy(t *testing.T) {
	const want = "memoized-secret"
	t.Setenv(envCAPassphrase, want)

	calls := 0
	m := &memoUnlocker{fn: func() ([]byte, error) {
		calls++
		return passphrase.Prompt("CA passphrase: ", envCAPassphrase)
	}}

	first, err := m.get()
	if err != nil {
		t.Fatalf("first get: %v", err)
	}
	if !bytes.Equal(first, []byte(want)) {
		t.Fatalf("first get = %q, want %q", first, want)
	}

	passphrase.Zero(first)

	second, err := m.get()
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if !bytes.Equal(second, []byte(want)) {
		t.Fatalf("second get = %q, want %q (cache was destroyed by consumer zeroing)", second, want)
	}
	if calls != 1 {
		t.Fatalf("fn invoked %d times, want exactly 1 (memoization broken)", calls)
	}
}

func TestNewPeerUnlockerMemoizesAcrossZeroing(t *testing.T) {
	const want = "peer-secret"
	t.Setenv(envPeerPassphrase, want)

	m := newPeerUnlocker()

	first, err := m.get()
	if err != nil {
		t.Fatalf("first get: %v", err)
	}
	passphrase.Zero(first)

	second, err := m.get()
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if !bytes.Equal(second, []byte(want)) {
		t.Fatalf("second peer get = %q, want %q; multi-peer push would fail for peer #2", second, want)
	}

	m.Zero()
	if m.got {
		t.Fatal("Zero did not clear got")
	}
}
