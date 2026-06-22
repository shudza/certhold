package db

import (
	"context"
	"fmt"

	"github.com/shudza/certhold/internal/peerfiles"
)

// ReachableHost is one row of the per-peer reachability view: a peer the named
// peer is allowed to SSH into, with the address and login user its Host block
// needs.
type ReachableHost struct {
	Name       string
	Address    string
	TargetUser string
}

// ReachableHosts returns every OTHER peer the named peer can reach: peers that
// are not revoked and accept inbound connections, and that either allow at least
// one of the named peer's groups, or — when the named peer is a member of the
// manager group — all such peers, since the manager principal on its cert is
// universally accepted. Resolved in a single query, ordered by name.
func (db *DB) ReachableHosts(ctx context.Context, peerName string) ([]ReachableHost, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT DISTINCT q.name, q.address, q.target_user
		 FROM peers q
		 WHERE q.name != ? AND q.revoked = 0 AND q.inbound = 1
		   AND (
		     EXISTS (SELECT 1 FROM peer_groups m WHERE m.peer_name = ? AND m.group_name = ?)
		     OR EXISTS (
		       SELECT 1 FROM peer_allowed_groups pag
		       JOIN peer_groups pg ON pg.group_name = pag.group_name
		       WHERE pag.peer_name = q.name AND pg.peer_name = ?
		     )
		   )
		 ORDER BY q.name`,
		peerName, peerName, peerfiles.ManagerPrincipal, peerName)
	if err != nil {
		return nil, fmt.Errorf("query reachable hosts: %w", err)
	}
	defer rows.Close()
	var out []ReachableHost
	for rows.Next() {
		var h ReachableHost
		if err := rows.Scan(&h.Name, &h.Address, &h.TargetUser); err != nil {
			return nil, fmt.Errorf("scan reachable host: %w", err)
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iter reachable hosts: %w", err)
	}
	return out, nil
}
