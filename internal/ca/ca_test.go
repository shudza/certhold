package ca

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if _, err := Generate(dir); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	ca, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, peerPubAK, peerPub, err := GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey: %v", err)
	}
	if len(peerPubAK) == 0 {
		t.Fatal("empty peer pub authorized key")
	}
	certBytes, serial, err := ca.SignCert(SignOptions{
		Pubkey:     peerPub,
		KeyID:      "test-peer",
		Principals: []string{"manager", "infra"},
	})
	if err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	if serial == 0 {
		t.Log("serial is zero (allowed but unlikely)")
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		t.Fatalf("parsed key is not *ssh.Certificate: %T", pk)
	}
	if cert.KeyId != "test-peer" {
		t.Errorf("KeyId = %q, want %q", cert.KeyId, "test-peer")
	}
	if got, want := cert.ValidPrincipals, []string{"manager", "infra"}; !equalStrings(got, want) {
		t.Errorf("ValidPrincipals = %v, want %v", got, want)
	}
	if cert.Serial != serial {
		t.Errorf("cert.Serial = %d, want %d", cert.Serial, serial)
	}
	caPub, _, _, _, err := ssh.ParseAuthorizedKey(ca.PublicKeyAuthorizedKey())
	if err != nil {
		t.Fatalf("parse CA pub: %v", err)
	}
	if !bytes.Equal(cert.SignatureKey.Marshal(), caPub.Marshal()) {
		t.Error("cert.SignatureKey does not match CA public key")
	}
}

func TestValidBeforeZeroIsInfinity(t *testing.T) {
	dir := t.TempDir()
	ca, err := Generate(dir)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	_, _, peerPub, err := GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey: %v", err)
	}
	certBytes, _, err := ca.SignCert(SignOptions{Pubkey: peerPub, KeyID: "x", Principals: []string{"x"}})
	if err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	cert := pk.(*ssh.Certificate)
	if cert.ValidBefore != ssh.CertTimeInfinity {
		t.Errorf("ValidBefore = %d, want CertTimeInfinity", cert.ValidBefore)
	}
}

func TestValidBeforeSpecific(t *testing.T) {
	dir := t.TempDir()
	ca, err := Generate(dir)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	_, _, peerPub, err := GeneratePeerKey()
	if err != nil {
		t.Fatalf("GeneratePeerKey: %v", err)
	}
	deadline := time.Now().Add(time.Hour).Truncate(time.Second)
	certBytes, _, err := ca.SignCert(SignOptions{Pubkey: peerPub, KeyID: "x", Principals: []string{"x"}, ValidBefore: deadline})
	if err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	pk, _, _, _, _ := ssh.ParseAuthorizedKey(certBytes)
	cert := pk.(*ssh.Certificate)
	if cert.ValidBefore != uint64(deadline.Unix()) {
		t.Errorf("ValidBefore = %d, want %d", cert.ValidBefore, deadline.Unix())
	}
}

func TestGenerateErrorsIfExists(t *testing.T) {
	dir := t.TempDir()
	if _, err := Generate(dir); err != nil {
		t.Fatalf("first Generate: %v", err)
	}
	if _, err := Generate(dir); err == nil {
		t.Fatal("second Generate: want error, got nil")
	}
}

func TestCAFileMode(t *testing.T) {
	dir := t.TempDir()
	if _, err := Generate(dir); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "ca"))
	if err != nil {
		t.Fatalf("stat ca: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Errorf("ca mode = %o, want 0600", mode)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
