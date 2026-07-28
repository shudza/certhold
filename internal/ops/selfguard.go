package ops

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/peerfiles"
)

// osHostname is a seam so tests can pin the resolved self name.
var osHostname = os.Hostname

// resolveSelfName returns certhold's own peer name: hostname when the caller
// has one, else os.Hostname(), mirroring how Rekey resolves it.
func resolveSelfName(hostname string) (string, error) {
	if hostname != "" {
		return hostname, nil
	}
	h, err := osHostname()
	if err != nil {
		return "", fmt.Errorf("hostname: %w", err)
	}
	return h, nil
}

// certPrincipals is the principal list a peer's cert carries: its own name
// followed by its groups. The manager's self row additionally carries the
// manager principal, which every peer authorizes inbound manager SSH with and
// which is never a DB group — a re-sign of the self cert that drops it locks
// the manager out of pushing to its whole fleet.
func certPrincipals(name string, groups []string, self bool) []string {
	out := make([]string, 0, len(groups)+2)
	out = append(out, name)
	if self {
		out = append(out, peerfiles.ManagerPrincipal)
	}
	for _, g := range groups {
		if self && g == peerfiles.ManagerPrincipal {
			continue
		}
		out = append(out, g)
	}
	return out
}

// guardNotSelfPeer refuses destructive peer operations aimed at the manager's
// own peer row (seeded once by init, named for the manager host). hostname is
// certhold's own peer name when the caller has one; empty means os.Hostname(),
// mirroring how Rekey resolves it. There is deliberately no escape hatch:
// deleting or altering the self row breaks rekey, revoke --rekey and all
// pushes, and nothing re-creates it short of manual DB surgery.
func guardNotSelfPeer(op, name, hostname string) error {
	hostname, err := resolveSelfName(hostname)
	if err != nil {
		return err
	}
	if name == hostname {
		return fmt.Errorf("refusing to %s certhold's own peer %q: this is the manager's self row; deleting or altering it breaks rekey, revoke --rekey and all pushes", op, name)
	}
	return nil
}

// selfCertKeyID resolves the manager's own peer name from its self cert under
// <data-dir>/self/<home>/.ssh/ (its KeyID is the name init enrolled the
// manager as). This is authoritative even when `init --hostname` named the
// manager differently from os.Hostname(), which the hostname-based guard alone
// cannot see. Empty when no self cert is found or parseable (fresh test
// environments) — callers treat that as "no extra signal".
func selfCertKeyID(dataDir, instanceKey string) string {
	certFile := peerfiles.V2CertFileName(instanceKey)
	candidates := []string{filepath.Join(dataDir, "self", "root", ".ssh", certFile)}
	if matches, err := filepath.Glob(filepath.Join(dataDir, "self", "home", "*", ".ssh", certFile)); err == nil {
		candidates = append(candidates, matches...)
	}
	for _, path := range candidates {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey(raw)
		if err != nil {
			continue
		}
		if cert, ok := pk.(*ssh.Certificate); ok {
			return cert.KeyId
		}
	}
	return ""
}
