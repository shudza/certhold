package ops

import (
	"context"
	"errors"
	"fmt"

	"github.com/shudza/certhold/internal/db"
)

// RemovePeer forgets a peer: it hard-deletes the peer and its referencing rows
// from manager state. It makes NO peer contact — no SSH dial, no CA work, no
// passphrase unlock. fleet_rev is bumped so other peers refresh on their next
// pull and drop the removed peer's Host alias. The peer's host is left
// untouched; use RevokePeer when the host must be cleaned and the CA rotated
// so the old cert stops being accepted.
func RemovePeer(ctx context.Context, deps Deps, name string) error {
	if err := guardNotSelfPeer("remove", name, ""); err != nil {
		return err
	}
	if _, err := deps.DB.GetPeer(ctx, name); err != nil {
		if errors.Is(err, db.ErrPeerNotFound) {
			return fmt.Errorf("remove peer %q: %w", name, err)
		}
		return fmt.Errorf("get peer %q: %w", name, err)
	}

	if err := deps.DB.DeletePeer(ctx, name); err != nil {
		return fmt.Errorf("remove peer %q: %w", name, err)
	}
	if err := deps.DB.BumpFleetRev(ctx); err != nil {
		return fmt.Errorf("bump fleet_rev: %w", err)
	}

	deps.info(name, fmt.Sprintf("Removed %s from manager state (no peer contact; its host was not touched).", name))
	return nil
}
