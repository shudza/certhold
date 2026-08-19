package ops

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/peerfiles"
)

// osHostname is a seam so tests can pin the resolved self name.
var osHostname = os.Hostname

// resolveSelfName returns certhold's own peer name: hostname when the caller
// has one, else the name persisted at init (the self_name meta key), else
// os.Hostname() for state written before the name was persisted. The OS
// hostname alone is wrong whenever `init --hostname` named the manager
// differently, or the host was renamed after init — the DB is authoritative.
func resolveSelfName(ctx context.Context, d *db.DB, hostname string) (string, error) {
	if hostname != "" {
		return hostname, nil
	}
	if d != nil {
		if v, ok, err := d.GetMeta(ctx, db.MetaSelfName); err == nil && ok && v != "" {
			return v, nil
		}
	}
	h, err := osHostname()
	if err != nil {
		return "", fmt.Errorf("hostname: %w", err)
	}
	return h, nil
}

// SelfName resolves certhold's own peer name for callers outside ops (CLI/TUI
// wiring): the name persisted at init, falling back to os.Hostname() for
// pre-feature state.
func SelfName(ctx context.Context, d *db.DB) (string, error) {
	return resolveSelfName(ctx, d, "")
}

// CertPrincipals is the principal list a peer's cert carries: its own name
// followed by its groups, each exactly once. The manager's self row
// additionally carries the manager principal, which every peer authorizes
// inbound manager SSH with and which is never a DB group — a re-sign of the
// self cert that drops it locks the manager out of pushing to its whole
// fleet. This is the single builder for every signing path (init, enroll,
// update, group cascades, rekey) so they cannot drift; a peer literally named
// "manager" still gets the principal once, not twice.
func CertPrincipals(name string, groups []string, self bool) []string {
	out := make([]string, 0, len(groups)+2)
	seen := map[string]struct{}{}
	add := func(p string) {
		if p == "" {
			return
		}
		if _, dup := seen[p]; dup {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	add(name)
	if self {
		add(peerfiles.ManagerPrincipal)
	}
	for _, g := range groups {
		if self && g == peerfiles.ManagerPrincipal {
			continue
		}
		add(g)
	}
	return out
}

// guardNotSelfPeer refuses destructive peer operations aimed at the manager's
// own peer row (seeded once by init). hostname is certhold's own peer name when
// the caller has one; empty resolves via resolveSelfName (persisted self name,
// then os.Hostname()). There is deliberately no escape hatch: deleting or
// altering the self row breaks rekey, revoke --rekey and all pushes, and
// nothing re-creates it short of manual DB surgery.
func guardNotSelfPeer(ctx context.Context, d *db.DB, op, name, hostname string) error {
	hostname, err := resolveSelfName(ctx, d, hostname)
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
