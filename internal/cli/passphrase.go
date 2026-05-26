package cli

import (
	"github.com/shudza/certhold/internal/passphrase"
)

const (
	envCAPassphrase   = "CERTHOLD_CA_PASSPHRASE"
	envPeerPassphrase = "CERTHOLD_PEER_PASSPHRASE"
)

// memoUnlocker wraps a prompt closure, caching the first successfully obtained
// passphrase so a multi-peer command prompts at most once. Cached bytes must be
// zeroed at command exit via Zero.
type memoUnlocker struct {
	fn     func() ([]byte, error)
	cached []byte
	got    bool
}

// get resolves the passphrase (prompting at most once) and returns a fresh copy
// of the cached bytes each call. Consumers may zero the returned slice without
// destroying the master cache, so a multi-peer command still succeeds for every
// peer. The master copy is wiped at command exit via Zero.
func (m *memoUnlocker) get() ([]byte, error) {
	if !m.got {
		pass, err := m.fn()
		if err != nil {
			return nil, err
		}
		m.cached = pass
		m.got = true
	}
	out := make([]byte, len(m.cached))
	copy(out, m.cached)
	return out, nil
}

// Zero wipes the cached passphrase. Safe to call when nothing was cached.
func (m *memoUnlocker) Zero() {
	if m.got {
		passphrase.Zero(m.cached)
		m.cached = nil
		m.got = false
	}
}

// newCAUnlocker returns a memoizing unlocker that resolves the CA passphrase from
// CERTHOLD_CA_PASSPHRASE or, failing that, a no-echo /dev/tty prompt.
func newCAUnlocker() *memoUnlocker {
	return &memoUnlocker{fn: func() ([]byte, error) {
		return passphrase.Prompt("CA passphrase: ", envCAPassphrase)
	}}
}

// newPeerUnlocker returns a memoizing unlocker for the manager peer passphrase.
func newPeerUnlocker() *memoUnlocker {
	return &memoUnlocker{fn: func() ([]byte, error) {
		return passphrase.Prompt("Manager peer passphrase: ", envPeerPassphrase)
	}}
}
