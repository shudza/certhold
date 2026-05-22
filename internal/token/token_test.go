package token

import (
	"encoding/base64"
	"testing"
)

func TestGenerateUnique(t *testing.T) {
	seen := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		tok, err := Generate()
		if err != nil {
			t.Fatalf("Generate[%d]: %v", i, err)
		}
		if _, ok := seen[tok]; ok {
			t.Fatalf("duplicate token at iteration %d: %s", i, tok)
		}
		seen[tok] = struct{}{}
	}
}

func TestGenerateLength(t *testing.T) {
	tok, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	want := base64.RawURLEncoding.EncodedLen(32)
	if len(tok) != want {
		t.Errorf("len(token) = %d, want %d", len(tok), want)
	}
	b, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	if len(b) != 32 {
		t.Errorf("decoded bytes = %d, want 32", len(b))
	}
}
