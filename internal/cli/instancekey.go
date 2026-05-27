package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/shudza/certhold/internal/db"
)

// generateInstanceKey returns 16 lowercase hex chars (8 random bytes). The key
// is filename-, sed-, and shell-safe so it can be interpolated into install
// scripts and namespaced file paths without escaping.
func generateInstanceKey() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// EnsureInstanceKey returns the stored per-instance key, generating and
// persisting one if absent. An upgraded legacy DB gets a stable key on its first
// v2 operation; the key never changes thereafter (rekey must not touch meta).
func EnsureInstanceKey(ctx context.Context, d *db.DB) (string, error) {
	if v, ok, err := d.GetMeta(ctx, db.MetaInstanceKey); err != nil {
		return "", err
	} else if ok {
		return v, nil
	}
	key, err := generateInstanceKey()
	if err != nil {
		return "", err
	}
	if err := d.SetMeta(ctx, db.MetaInstanceKey, key); err != nil {
		return "", err
	}
	return key, nil
}
