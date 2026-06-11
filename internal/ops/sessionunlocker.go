package ops

import (
	"sync"

	"github.com/shudza/certhold/internal/passphrase"
)

// SessionUnlocker is a session-scoped passphrase handle: it wraps a prompt
// closure, caching the first successfully obtained passphrase so a multi-peer
// operation prompts at most once. Cached bytes must be zeroed at session exit
// via Close (or Forget, which additionally re-arms the prompt).
type SessionUnlocker struct {
	mu     sync.Mutex
	prompt func() ([]byte, error)
	cached []byte
	got    bool
}

func NewSessionUnlocker(prompt func() ([]byte, error)) *SessionUnlocker {
	return &SessionUnlocker{prompt: prompt}
}

// Get resolves the passphrase (prompting at most once) and returns a fresh
// copy of the cached bytes each call. Consumers may zero the returned slice
// without destroying the master cache, so a multi-peer operation still
// succeeds for every peer.
func (s *SessionUnlocker) Get() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.got {
		pass, err := s.prompt()
		if err != nil {
			return nil, err
		}
		s.cached = pass
		s.got = true
	}
	out := make([]byte, len(s.cached))
	copy(out, s.cached)
	return out, nil
}

// Forget zeroes the cached passphrase and re-arms the prompt: the next Get
// prompts again. Safe to call when nothing was cached.
func (s *SessionUnlocker) Forget() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.got {
		passphrase.Zero(s.cached)
		s.cached = nil
		s.got = false
	}
}

// Close zeroes the cached passphrase. Safe to call when nothing was cached.
func (s *SessionUnlocker) Close() {
	s.Forget()
}
