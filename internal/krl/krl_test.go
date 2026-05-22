package krl

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shudza/certhold/internal/ca"
)

func requireSshKeygen(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH, skipping")
	}
}

func setupCA(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	caDir := filepath.Join(dir, "ca")
	if _, err := ca.Generate(caDir); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	return filepath.Join(caDir, "ca.pub")
}

func TestBuildEmptyKRL(t *testing.T) {
	requireSshKeygen(t)
	caPub := setupCA(t)
	data, err := Build(context.Background(), caPub, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("empty bytes returned")
	}
	if !bytes.HasPrefix(data, []byte("SSHKRL")) {
		t.Errorf("KRL header does not start with SSHKRL: %x", data[:8])
	}
}

func TestBuildWithSerial(t *testing.T) {
	requireSshKeygen(t)
	caPub := setupCA(t)
	const serial = uint64(0x1234)
	data, err := Build(context.Background(), caPub, []uint64{serial})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !bytes.HasPrefix(data, []byte("SSHKRL")) {
		t.Errorf("KRL header does not start with SSHKRL: %x", data[:8])
	}

	tmp := filepath.Join(t.TempDir(), "krl.bin")
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		t.Fatalf("write KRL: %v", err)
	}
	out, err := exec.Command("ssh-keygen", "-lQf", tmp).Output()
	if err != nil {
		t.Fatalf("ssh-keygen -lQf: %v", err)
	}
	if !strings.Contains(string(out), "serial: 4660") {
		t.Errorf("expected serial 4660 (0x1234) in KRL listing, got:\n%s", out)
	}
}

func TestBuildMultipleSerials(t *testing.T) {
	requireSshKeygen(t)
	caPub := setupCA(t)
	serials := []uint64{0x1111, 0x2222, 0x3333}
	data, err := Build(context.Background(), caPub, serials)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	tmp := filepath.Join(t.TempDir(), "krl.bin")
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		t.Fatalf("write KRL: %v", err)
	}
	out, err := exec.Command("ssh-keygen", "-lQf", tmp).Output()
	if err != nil {
		t.Fatalf("ssh-keygen -lQf: %v", err)
	}
	for _, want := range []string{"4369", "8738", "13107"} {
		if !strings.Contains(string(out), "serial: "+want) {
			t.Errorf("missing serial %s in KRL listing:\n%s", want, out)
		}
	}
}

func TestBuildBadCAPath(t *testing.T) {
	requireSshKeygen(t)
	_, err := Build(context.Background(), "/nonexistent/ca.pub", []uint64{1})
	if err == nil {
		t.Fatal("expected error for missing CA pub")
	}
}
