package ca

import (
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func signWith(t *testing.T, c *CA) {
	t.Helper()
	_, _, pub, err := GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey: %v", err)
	}
	if _, _, err := c.SignCert(SignOptions{Pubkey: pub, KeyID: "k", Principals: []string{"k"}}); err != nil {
		t.Fatalf("SignCert: %v", err)
	}
}

func TestEncryptedCARoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	pass := []byte("s3cret")
	if _, err := GenerateWithPassphrase(dir, pass); err != nil {
		t.Fatalf("GenerateWithPassphrase: %v", err)
	}

	// Plaintext Load must fail (key is encrypted).
	if _, err := Load(dir); err == nil {
		t.Fatal("Load on encrypted key: want error, got nil")
	}

	called := false
	c, err := LoadWithPassphrase(dir, func() ([]byte, error) {
		called = true
		return []byte("s3cret"), nil
	})
	if err != nil {
		t.Fatalf("LoadWithPassphrase: %v", err)
	}
	if !called {
		t.Error("unlock callback was not invoked for an encrypted key")
	}
	signWith(t, c)
}

func TestPlaintextCASkipsUnlock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	if _, err := GenerateWithPassphrase(dir, nil); err != nil {
		t.Fatalf("GenerateWithPassphrase(nil): %v", err)
	}
	c, err := LoadWithPassphrase(dir, func() ([]byte, error) {
		t.Fatal("unlock must not be called for a plaintext key")
		return nil, nil
	})
	if err != nil {
		t.Fatalf("LoadWithPassphrase: %v", err)
	}
	signWith(t, c)
}

func TestWrongCAPassphraseErrors(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	if _, err := GenerateWithPassphrase(dir, []byte("right")); err != nil {
		t.Fatalf("GenerateWithPassphrase: %v", err)
	}
	if _, err := LoadWithPassphrase(dir, func() ([]byte, error) {
		return []byte("wrong"), nil
	}); err == nil {
		t.Fatal("LoadWithPassphrase with wrong passphrase: want error, got nil")
	}
}

func TestEncryptedCANilUnlockErrors(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	if _, err := GenerateWithPassphrase(dir, []byte("pw")); err != nil {
		t.Fatalf("GenerateWithPassphrase: %v", err)
	}
	if _, err := LoadWithPassphrase(dir, nil); err == nil {
		t.Fatal("LoadWithPassphrase(nil) on encrypted key: want error, got nil")
	}
}

func TestLoadPublicKeyNoPrompt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	c, err := GenerateWithPassphrase(dir, []byte("pw"))
	if err != nil {
		t.Fatalf("GenerateWithPassphrase: %v", err)
	}
	pub, err := LoadPublicKey(dir)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	if string(pub) != string(c.PublicKeyAuthorizedKey()) {
		t.Error("LoadPublicKey bytes differ from generated CA pubkey")
	}
}

func TestEncryptedPeerKeyRoundTrip(t *testing.T) {
	pass := []byte("peerpw")
	privPEM, _, _, err := GeneratePeerKeyWithPassphrase(pass)
	if err != nil {
		t.Fatalf("GeneratePeerKeyWithPassphrase: %v", err)
	}
	if _, err := ssh.ParseRawPrivateKey(privPEM); err == nil {
		t.Fatal("plaintext parse of encrypted peer key: want error, got nil")
	}
	if _, err := ssh.ParseRawPrivateKeyWithPassphrase(privPEM, []byte("peerpw")); err != nil {
		t.Fatalf("ParseRawPrivateKeyWithPassphrase: %v", err)
	}
	if _, err := ssh.ParseRawPrivateKeyWithPassphrase(privPEM, []byte("bad")); err == nil {
		t.Fatal("wrong peer passphrase: want error, got nil")
	}
}

func TestPlaintextPeerKeyParses(t *testing.T) {
	privPEM, _, _, err := GeneratePeerKeyWithPassphrase(nil)
	if err != nil {
		t.Fatalf("GeneratePeerKeyWithPassphrase(nil): %v", err)
	}
	if _, err := ssh.ParseRawPrivateKey(privPEM); err != nil {
		t.Fatalf("ParseRawPrivateKey plaintext: %v", err)
	}
}
