package cli

import (
	"crypto/sha256"
	"encoding/base64"
	"net"
	"strings"
	"testing"
)

func TestGenerateSelfSigned_IPHost(t *testing.T) {
	cert, der, err := generateSelfSigned("192.168.1.205:8443")
	if err != nil {
		t.Fatalf("generateSelfSigned: %v", err)
	}
	if cert.Leaf == nil {
		t.Fatal("Leaf nil")
	}
	if len(der) == 0 {
		t.Fatal("der empty")
	}

	wantIPs := []string{"192.168.1.205", "127.0.0.1", "::1"}
	for _, w := range wantIPs {
		found := false
		for _, ip := range cert.Leaf.IPAddresses {
			if ip.Equal(net.ParseIP(w)) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing IP SAN %q; got %v", w, cert.Leaf.IPAddresses)
		}
	}

	foundLocal := false
	for _, d := range cert.Leaf.DNSNames {
		if d == "localhost" {
			foundLocal = true
		}
	}
	if !foundLocal {
		t.Errorf("missing 'localhost' DNSName; got %v", cert.Leaf.DNSNames)
	}
}

func TestGenerateSelfSigned_DNSHost(t *testing.T) {
	cert, _, err := generateSelfSigned("certhold.home.lan:8443")
	if err != nil {
		t.Fatalf("generateSelfSigned: %v", err)
	}
	foundName := false
	for _, d := range cert.Leaf.DNSNames {
		if d == "certhold.home.lan" {
			foundName = true
		}
	}
	if !foundName {
		t.Errorf("expected DNSName 'certhold.home.lan'; got %v", cert.Leaf.DNSNames)
	}
	if len(cert.Leaf.IPAddresses) < 2 {
		t.Errorf("expected at least 2 IPs (127.0.0.1, ::1); got %v", cert.Leaf.IPAddresses)
	}
}

func TestGenerateSelfSigned_EmptyHost(t *testing.T) {
	cert, _, err := generateSelfSigned("")
	if err != nil {
		t.Fatalf("generateSelfSigned: %v", err)
	}
	for _, w := range []string{"127.0.0.1", "::1"} {
		found := false
		for _, ip := range cert.Leaf.IPAddresses {
			if ip.Equal(net.ParseIP(w)) {
				found = true
			}
		}
		if !found {
			t.Errorf("missing IP %q; got %v", w, cert.Leaf.IPAddresses)
		}
	}
	foundLocal := false
	for _, d := range cert.Leaf.DNSNames {
		if d == "localhost" {
			foundLocal = true
		}
	}
	if !foundLocal {
		t.Errorf("missing 'localhost' DNSName; got %v", cert.Leaf.DNSNames)
	}
}

func TestGenerateSelfSigned_PortOnly(t *testing.T) {
	cert, _, err := generateSelfSigned(":8443")
	if err != nil {
		t.Fatalf("generateSelfSigned: %v", err)
	}
	if len(cert.Leaf.IPAddresses) < 2 {
		t.Errorf("expected at least 2 IPs; got %v", cert.Leaf.IPAddresses)
	}
}

func TestCertFingerprint(t *testing.T) {
	der := []byte("hello world")
	fp := certFingerprint(der)
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Errorf("missing SHA256: prefix: %q", fp)
	}
	rest := strings.TrimPrefix(fp, "SHA256:")
	if strings.Contains(rest, "=") {
		t.Errorf("padding not stripped: %q", fp)
	}
	if len(rest) != 43 {
		t.Errorf("expected 43 chars after prefix; got %d (%q)", len(rest), rest)
	}

	sum := sha256.Sum256(der)
	want := strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
	if rest != want {
		t.Errorf("fingerprint = %q, want %q", rest, want)
	}
}

func TestCertFingerprint_OnGeneratedCert(t *testing.T) {
	_, der, err := generateSelfSigned("127.0.0.1:0")
	if err != nil {
		t.Fatalf("generateSelfSigned: %v", err)
	}
	fp := certFingerprint(der)
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Errorf("missing SHA256: prefix: %q", fp)
	}
	if len(strings.TrimPrefix(fp, "SHA256:")) != 43 {
		t.Errorf("unexpected fingerprint length: %q", fp)
	}
}
