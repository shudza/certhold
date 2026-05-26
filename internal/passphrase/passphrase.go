// Package passphrase reads at-rest key passphrases from the controlling terminal
// without echo, falling back to an environment variable for non-interactive use.
package passphrase

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

// ErrNoTTY is returned when neither the env var nor /dev/tty is available, so a
// prompt would otherwise hang forever (e.g. CI with no controlling terminal).
var ErrNoTTY = errors.New("no /dev/tty available for passphrase prompt")

// ErrMismatch is returned by PromptConfirm when the two entries differ.
var ErrMismatch = errors.New("passphrases do not match")

// Prompt resolves a passphrase: if envVar is set and non-empty its value is
// returned immediately (automation / CI path); otherwise it reads one line from
// /dev/tty with echo disabled. The env var is always checked before touching the
// tty so CI never blocks.
func Prompt(prompt, envVar string) ([]byte, error) {
	if envVar != "" {
		if v, ok := os.LookupEnv(envVar); ok && v != "" {
			return []byte(v), nil
		}
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, ErrNoTTY
	}
	defer tty.Close()
	if _, err := fmt.Fprint(tty, prompt); err != nil {
		return nil, fmt.Errorf("write prompt: %w", err)
	}
	pass, err := term.ReadPassword(int(tty.Fd()))
	_, _ = fmt.Fprintln(tty)
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	return pass, nil
}

// promptOnce is the single-line reader used by PromptConfirm; overridable in
// tests so the mismatch branch can be exercised without a tty.
var promptOnce = func(prompt string) ([]byte, error) {
	return Prompt(prompt, "")
}

// PromptConfirm prompts twice and errors if the two entries differ. When envVar
// is set its value is used directly without a second prompt (no echo to confirm
// against in automation).
func PromptConfirm(prompt, envVar string) ([]byte, error) {
	if envVar != "" {
		if v, ok := os.LookupEnv(envVar); ok && v != "" {
			return []byte(v), nil
		}
	}
	first, err := promptOnce(prompt)
	if err != nil {
		return nil, err
	}
	second, err := promptOnce("Confirm " + prompt)
	if err != nil {
		Zero(first)
		return nil, err
	}
	if string(first) != string(second) {
		Zero(first)
		Zero(second)
		return nil, ErrMismatch
	}
	Zero(second)
	return first, nil
}

// Zero overwrites b in place so the passphrase does not linger in memory.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
