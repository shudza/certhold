package ops

import (
	"bytes"
	"errors"
	"testing"
)

func TestSessionUnlockerPromptsOnceAcrossGets(t *testing.T) {
	calls := 0
	s := NewSessionUnlocker(func() ([]byte, error) {
		calls++
		return []byte("secret"), nil
	})

	first, err := s.Get()
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}
	if !bytes.Equal(first, []byte("secret")) {
		t.Fatalf("first Get = %q", first)
	}

	for i := range first {
		first[i] = 0
	}

	second, err := s.Get()
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if !bytes.Equal(second, []byte("secret")) {
		t.Fatalf("second Get = %q, want %q (consumer zeroing destroyed the cache)", second, "secret")
	}
	if calls != 1 {
		t.Fatalf("prompt invoked %d times, want exactly 1", calls)
	}
}

func TestSessionUnlockerForgetReprompts(t *testing.T) {
	calls := 0
	s := NewSessionUnlocker(func() ([]byte, error) {
		calls++
		return []byte("secret"), nil
	})

	if _, err := s.Get(); err != nil {
		t.Fatalf("Get: %v", err)
	}
	s.Forget()
	if _, err := s.Get(); err != nil {
		t.Fatalf("Get after Forget: %v", err)
	}
	if calls != 2 {
		t.Fatalf("prompt invoked %d times, want 2 (Forget must re-arm the prompt)", calls)
	}
}

func TestSessionUnlockerCloseZeroes(t *testing.T) {
	s := NewSessionUnlocker(func() ([]byte, error) {
		return []byte("secret"), nil
	})
	if _, err := s.Get(); err != nil {
		t.Fatalf("Get: %v", err)
	}

	cached := s.cached
	s.Close()
	for i, b := range cached {
		if b != 0 {
			t.Fatalf("cached[%d] = %d, want 0 (Close must zero the master copy)", i, b)
		}
	}
	if s.got || s.cached != nil {
		t.Fatal("Close must clear the cached state")
	}
}

func TestSessionUnlockerPromptErrorNotCached(t *testing.T) {
	calls := 0
	s := NewSessionUnlocker(func() ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("tty gone")
		}
		return []byte("secret"), nil
	})

	if _, err := s.Get(); err == nil {
		t.Fatal("expected first Get to fail")
	}
	got, err := s.Get()
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if !bytes.Equal(got, []byte("secret")) {
		t.Fatalf("second Get = %q, want %q", got, "secret")
	}
}
