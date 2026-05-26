package passphrase

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

func TestPromptEnvVar(t *testing.T) {
	t.Setenv("TEST_PASS", "hunter2")
	got, err := Prompt("ignored: ", "TEST_PASS")
	if err != nil {
		t.Fatalf("Prompt: %v", err)
	}
	if string(got) != "hunter2" {
		t.Errorf("got %q, want hunter2", got)
	}
}

func TestPromptConfirmEnvVar(t *testing.T) {
	t.Setenv("TEST_PASS", "secret")
	got, err := PromptConfirm("ignored: ", "TEST_PASS")
	if err != nil {
		t.Fatalf("PromptConfirm: %v", err)
	}
	if string(got) != "secret" {
		t.Errorf("got %q, want secret", got)
	}
}

func TestPromptNoTTY(t *testing.T) {
	if _, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		t.Skip("a controlling tty is available; cannot exercise ErrNoTTY path")
	}
	t.Setenv("TEST_PASS_EMPTY", "")
	_, err := Prompt("p: ", "TEST_PASS_EMPTY")
	if !errors.Is(err, ErrNoTTY) {
		t.Errorf("Prompt without env or tty: %v, want ErrNoTTY", err)
	}
}

func TestPromptConfirmMismatch(t *testing.T) {
	calls := 0
	orig := promptOnce
	promptOnce = func(string) ([]byte, error) {
		calls++
		if calls == 1 {
			return []byte("aaa"), nil
		}
		return []byte("bbb"), nil
	}
	defer func() { promptOnce = orig }()

	_, err := PromptConfirm("p: ", "")
	if !errors.Is(err, ErrMismatch) {
		t.Errorf("PromptConfirm mismatch: %v, want ErrMismatch", err)
	}
}

func TestPromptConfirmMatch(t *testing.T) {
	orig := promptOnce
	promptOnce = func(string) ([]byte, error) { return []byte("same"), nil }
	defer func() { promptOnce = orig }()

	got, err := PromptConfirm("p: ", "")
	if err != nil {
		t.Fatalf("PromptConfirm: %v", err)
	}
	if string(got) != "same" {
		t.Errorf("got %q, want same", got)
	}
}

func TestZero(t *testing.T) {
	b := []byte("topsecret")
	Zero(b)
	if !bytes.Equal(b, make([]byte, len(b))) {
		t.Errorf("Zero left non-zero bytes: %v", b)
	}
}
