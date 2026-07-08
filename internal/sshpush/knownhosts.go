package sshpush

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// AppendKnownHost appends a known_hosts entry for addr's host key to the file
// at path, creating the parent dir (0700) and file (0644) if absent. The line
// format matches knownhosts.Line, so a subsequent knownhosts.New on the same
// path will accept it. An already-present (host, key) pair is not appended
// again, so repeated captures stay idempotent. addr may carry a port
// (host:port); it is normalized to the known_hosts form (bare host for :22).
func AppendKnownHost(path, addr string, key ssh.PublicKey) error {
	if key == nil {
		return errors.New("sshpush: nil host key")
	}
	normalized := knownhosts.Normalize(addr)
	line := knownhosts.Line([]string{normalized}, key) + "\n"

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	if _, err := os.Stat(path); err == nil {
		if knownHostMatches(path, normalized, key) {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("append %s: %w", path, err)
	}
	return nil
}

// knownHostMatches reports whether the file at path already accepts key for the
// given normalized host (so AppendKnownHost can dedupe). Any read/parse error
// is treated as "not present" — the caller then appends, and a malformed file
// surfaces later through the strict push callback rather than here.
func knownHostMatches(path, normalizedHost string, key ssh.PublicKey) bool {
	cb, err := knownhosts.New(path)
	if err != nil {
		return false
	}
	host := normalizedHost
	if _, _, splitErr := net.SplitHostPort(host); splitErr != nil {
		host = net.JoinHostPort(host, "22")
	}
	fakeAddr := &net.TCPAddr{IP: net.IPv4zero, Port: 22}
	return cb(host, fakeAddr, key) == nil
}

// capturingCallback wraps a strict knownhosts callback so that a presented host
// key which is *unknown* (no entry yet) is accepted and recorded, while a
// *mismatch* against an existing entry still fails. This is the enroll-time
// capture path: the first contact with a peer learns its key (TOFU-once),
// later pushes stay strict. Host-key CHANGES (mismatch) are deliberately not
// auto-accepted — that is the out-of-scope reinstall/relearn case.
//
// An optional confirm fn gates the unknown-host accept: when set it is consulted
// on an unknown host (true -> accept+record, false -> reject with the original
// strict error, error -> abort the dial with that error). It is never consulted
// on a mismatch. When confirm is nil the unknown host is auto-accepted (enroll).
type capturingCallback struct {
	strict  ssh.HostKeyCallback
	confirm func(host string, key ssh.PublicKey) (bool, error)
	host    string
	// pauseTimeout/resumeTimeout, when set, bracket the confirm fn so the dial's
	// connect timer cannot fire while a human is deciding (Dial wires them only
	// when it owns the timeout, i.e. the caller's ctx had no deadline).
	pauseTimeout  func()
	resumeTimeout func()
	mu            sync.Mutex
	key           ssh.PublicKey
}

func (c *capturingCallback) callback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	err := c.strict(hostname, remote, key)
	if err == nil {
		return nil
	}
	var keyErr *knownhosts.KeyError
	if errors.As(err, &keyErr) && len(keyErr.Want) == 0 {
		// Host is unknown (no entry).
		if c.confirm != nil {
			if c.pauseTimeout != nil {
				c.pauseTimeout()
			}
			ok, cerr := c.confirm(c.host, key)
			if c.resumeTimeout != nil {
				c.resumeTimeout()
			}
			if cerr != nil {
				return cerr
			}
			if !ok {
				return err
			}
		}
		// Accept and record for capture.
		c.mu.Lock()
		c.key = key
		c.mu.Unlock()
		return nil
	}
	// Mismatch (len(Want) > 0), revoked, or any other error: stay strict.
	return err
}

func (c *capturingCallback) captured() ssh.PublicKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.key
}
