package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

func GeneratePeerKey() (privPEM []byte, pubAuthorizedKey []byte, sshPub ssh.PublicKey, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ed25519 keygen: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "certhold-peer")
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
