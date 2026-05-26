package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// GeneratePeerKey generates a plaintext peer key pair. Thin wrapper over
// GeneratePeerKeyWithPassphrase with a nil passphrase.
func GeneratePeerKey() (privPEM []byte, pubAuthorizedKey []byte, sshPub ssh.PublicKey, err error) {
	return GeneratePeerKeyWithPassphrase(nil)
}

// GeneratePeerKeyWithPassphrase generates a peer key pair, encrypting the private
// key with passphrase when len(passphrase) > 0 and writing plaintext otherwise.
func GeneratePeerKeyWithPassphrase(pass []byte) (privPEM []byte, pubAuthorizedKey []byte, sshPub ssh.PublicKey, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ed25519 keygen: %w", err)
	}
	var block *pem.Block
	if len(pass) > 0 {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "certhold-peer", pass)
	} else {
		block, err = ssh.MarshalPrivateKey(priv, "certhold-peer")
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshal private key: %w", err)
	}
	privPEM = pem.EncodeToMemory(block)
	sshPub, err = ssh.NewPublicKey(pub)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new public key: %w", err)
	}
	pubAuthorizedKey = ssh.MarshalAuthorizedKey(sshPub)
	return privPEM, pubAuthorizedKey, sshPub, nil
}
