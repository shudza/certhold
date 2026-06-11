package cli

import (
	"github.com/shudza/certhold/internal/ops"
	"github.com/shudza/certhold/internal/passphrase"
)

const (
	envCAPassphrase   = "CERTHOLD_CA_PASSPHRASE"
	envPeerPassphrase = "CERTHOLD_PEER_PASSPHRASE"
)

// memoUnlocker adapts ops.SessionUnlocker to the historical get/Zero call
// sites in this package.
type memoUnlocker struct {
	s *ops.SessionUnlocker
}

func newMemoUnlocker(fn func() ([]byte, error)) *memoUnlocker {
	return &memoUnlocker{s: ops.NewSessionUnlocker(fn)}
}

func (m *memoUnlocker) get() ([]byte, error) { return m.s.Get() }

func (m *memoUnlocker) Zero() { m.s.Close() }

// newCAUnlocker returns a memoizing unlocker that resolves the CA passphrase from
// CERTHOLD_CA_PASSPHRASE or, failing that, a no-echo /dev/tty prompt.
func newCAUnlocker() *memoUnlocker {
	return newMemoUnlocker(func() ([]byte, error) {
		return passphrase.Prompt("CA passphrase: ", envCAPassphrase)
	})
}

// newPeerUnlocker returns a memoizing unlocker for the manager peer passphrase.
func newPeerUnlocker() *memoUnlocker {
	return newMemoUnlocker(func() ([]byte, error) {
		return passphrase.Prompt("Manager peer passphrase: ", envPeerPassphrase)
	})
}
