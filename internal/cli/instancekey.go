package cli

import (
	"context"

	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/ops"
)

// EnsureInstanceKey returns the stored per-instance key, generating and
// persisting one if absent. An upgraded legacy DB gets a stable key on its first
// v2 operation; the key never changes thereafter (rekey must not touch meta).
func EnsureInstanceKey(ctx context.Context, d *db.DB) (string, error) {
	return ops.EnsureInstanceKey(ctx, d)
}
