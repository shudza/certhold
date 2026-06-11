package ops

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/shudza/certhold/internal/db"
)

// RevokePeer marks a peer revoked, then rotates the CA around it via a partial
// rekey so its old (now CA-retired) cert stops being accepted across the
// fleet. hostname is certhold's own peer name; empty means os.Hostname().
func RevokePeer(ctx context.Context, deps Deps, name, hostname string) error {
	if _, err := deps.DB.GetPeer(ctx, name); err != nil {
		if errors.Is(err, db.ErrPeerNotFound) {
			return fmt.Errorf("revoke peer %q: %w", name, err)
		}
		return fmt.Errorf("get peer %q: %w", name, err)
	}

	if err := deps.DB.SetPeerRevoked(ctx, name); err != nil {
		return fmt.Errorf("revoke peer %q: %w", name, err)
	}

	if hostname == "" {
		h, herr := os.Hostname()
		if herr != nil {
			return fmt.Errorf("hostname: %w", herr)
		}
		hostname = h
	}
	if err := Rekey(ctx, deps, RekeyOptions{
		Hostname: hostname,
		Exclude:  map[string]bool{name: true},
	}); err != nil {
		return fmt.Errorf("rekey-revoke: %w", err)
	}
	deps.info(name, fmt.Sprintf("Revoked %s via CA rekey.", name))
	return nil
}
