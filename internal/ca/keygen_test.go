package ca

import (
	"crypto/ed25519"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGeneratePeerKeyParsesBack(t *testing.T) {
	privPEM, pubAK, sshPub, err := GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey: %v", err)
	}
	if len(privPEM) == 0 || len(pubAK) == 0 || sshPub == nil {
		t.Fatal("empty outputs")
	}
	raw, err := ssh.ParseRawPrivateKey(privPEM)
	if err != nil {
		t.Fatalf("ParseRawPrivateKey: %v", err)
	}
	priv, ok := raw.(*ed25519.PrivateKey)
	if !ok {
		t.Fatalf("parsed key is not *ed25519.PrivateKey: %T", raw)
	}
	if len(*priv) != ed25519.PrivateKeySize {
		t.Errorf("private key size = %d, want %d", len(*priv), ed25519.PrivateKeySize)
	}
}
