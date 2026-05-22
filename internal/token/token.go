package token

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func Generate() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
