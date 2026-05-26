// Package ca implements the SSH certificate authority and peer cert signing.
package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/passphrase"
)

type CA struct {
	signer           ssh.Signer
	pubAuthorizedKey []byte
}

type SignOptions struct {
	Pubkey      ssh.PublicKey
	KeyID       string
	Principals  []string
	ValidBefore time.Time
}

// Generate writes a plaintext (unencrypted) CA key pair. Thin wrapper over
// GenerateWithPassphrase with a nil passphrase, kept for tests and callers that
// have opted out of at-rest protection.
func Generate(dir string) (*CA, error) {
	return GenerateWithPassphrase(dir, nil)
}

// GenerateWithPassphrase writes a CA key pair, encrypting the private key with
// passphrase when len(passphrase) > 0 and writing it in plaintext otherwise.
func GenerateWithPassphrase(dir string, pass []byte) (*CA, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}
	privPath := filepath.Join(dir, "ca")
	pubPath := filepath.Join(dir, "ca.pub")
	for _, p := range []string{privPath, pubPath} {
		if _, err := os.Stat(p); err == nil {
			return nil, fmt.Errorf("ca file already exists: %s", p)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("stat %s: %w", p, err)
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519 keygen: %w", err)
	}
	var block *pem.Block
	if len(pass) > 0 {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "certhold-ca", pass)
	} else {
		block, err = ssh.MarshalPrivateKey(priv, "certhold-ca")
	}
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(block)
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("new public key: %w", err)
	}
	pubBytes := ssh.MarshalAuthorizedKey(sshPub)
	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		return nil, fmt.Errorf("write %s: %w", privPath, err)
	}
	if err := os.WriteFile(pubPath, pubBytes, 0644); err != nil {
		return nil, fmt.Errorf("write %s: %w", pubPath, err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("new signer: %w", err)
	}
	return &CA{signer: signer, pubAuthorizedKey: pubBytes}, nil
}

// Load reads a plaintext CA key pair. It fails on an encrypted key; use
// LoadWithPassphrase for keys that may be passphrase-protected.
func Load(dir string) (*CA, error) {
	return LoadWithPassphrase(dir, nil)
}

// LoadWithPassphrase reads a CA key pair, transparently handling both plaintext
// and passphrase-encrypted private keys. A plaintext key parses on the first try
// and unlock is never invoked (existing plaintext deployments need no prompt).
// An encrypted key triggers unlock() to obtain the passphrase; unlock may be nil
// only when the key is known to be plaintext.
func LoadWithPassphrase(dir string, unlock func() ([]byte, error)) (*CA, error) {
	privPath := filepath.Join(dir, "ca")
	pubPath := filepath.Join(dir, "ca.pub")
	privBytes, err := os.ReadFile(privPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", privPath, err)
	}
	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", pubPath, err)
	}
	signer, err := ssh.ParsePrivateKey(privBytes)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if !errors.As(err, &missing) {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		if unlock == nil {
			return nil, fmt.Errorf("ca key %s is passphrase-protected but no passphrase source was provided", privPath)
		}
		pass, uerr := unlock()
		if uerr != nil {
			return nil, fmt.Errorf("obtain ca passphrase: %w", uerr)
		}
		signer, err = ssh.ParsePrivateKeyWithPassphrase(privBytes, pass)
		passphrase.Zero(pass)
		if err != nil {
			return nil, fmt.Errorf("parse encrypted private key: %w", err)
		}
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey(pubBytes); err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	return &CA{signer: signer, pubAuthorizedKey: pubBytes}, nil
}

// LoadPublicKey returns just the CA's public key (authorized_keys form), reading
// only ca.pub. Used by commands that never sign (e.g. group) so they never need
// the CA passphrase.
func LoadPublicKey(dir string) ([]byte, error) {
	pubPath := filepath.Join(dir, "ca.pub")
	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", pubPath, err)
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey(pubBytes); err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	return pubBytes, nil
}

func (c *CA) PublicKeyAuthorizedKey() []byte {
	return c.pubAuthorizedKey
}

func (c *CA) SignCert(opts SignOptions) ([]byte, uint64, error) {
	var sb [8]byte
	if _, err := rand.Read(sb[:]); err != nil {
		return nil, 0, fmt.Errorf("random serial: %w", err)
	}
	serial := binary.BigEndian.Uint64(sb[:])
	var validBefore uint64
	if opts.ValidBefore.IsZero() {
		validBefore = ssh.CertTimeInfinity
	} else {
		validBefore = uint64(opts.ValidBefore.Unix())
	}
	cert := &ssh.Certificate{
		Key:             opts.Pubkey,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           opts.KeyID,
		ValidPrincipals: opts.Principals,
		ValidAfter:      0,
		ValidBefore:     validBefore,
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-X11-forwarding":   "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		},
	}
	if err := cert.SignCert(rand.Reader, c.signer); err != nil {
		return nil, 0, fmt.Errorf("sign cert: %w", err)
	}
	return ssh.MarshalAuthorizedKey(cert), serial, nil
}
