package peerfiles

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"testing"
)

type extracted struct {
	mode int64
	data []byte
}

func extract(t *testing.T, archive []byte) map[string]extracted {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := map[string]extracted{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		out[hdr.Name] = extracted{mode: hdr.Mode, data: data}
	}
	return out
}

func sampleInputs() PeerFiles {
	return PeerFiles{
		Hostname:           "host1",
		PrivKey:            []byte("PRIVKEY"),
		CertPub:            []byte("CERTPUB"),
		CAPub:              []byte("CAPUB"),
		KRL:                []byte("KRLDATA"),
		AuthPrincipalsRoot: []string{"infra", "databases"},
		CAKnownHostsEntry:  "@cert-authority * ssh-ed25519 AAAATEST",
	}
}

func TestBuild_AllEntriesAndModes(t *testing.T) {
	data, err := Build(sampleInputs())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	got := extract(t, data)

	expected := map[string]int64{
		"etc/ssh/peer_ed25519":                0600,
		"etc/ssh/peer_ed25519-cert.pub":       0644,
		"etc/ssh/ca.pub":                      0644,
		"etc/ssh/krl":                         0644,
		"etc/ssh/sshd_config.d/certhold.conf": 0644,
		"etc/ssh/auth_principals/root":        0644,
		"etc/ssh/ca_known_hosts":              0644,
		"etc/ssh/ssh_config.d/certhold.conf":  0644,
	}

	if len(got) != len(expected) {
		t.Fatalf("entry count: got %d want %d (entries=%v)", len(got), len(expected), keys(got))
	}
	for name, mode := range expected {
		e, ok := got[name]
		if !ok {
			t.Errorf("missing entry %q", name)
			continue
		}
		if e.mode != mode {
			t.Errorf("%s mode: got %o want %o", name, e.mode, mode)
		}
	}

	if !bytes.HasPrefix(got["etc/ssh/auth_principals/root"].data, []byte("manager\n")) {
		t.Errorf("auth_principals/root does not start with manager: %q", got["etc/ssh/auth_principals/root"].data)
	}
	if want := "manager\ninfra\ndatabases\n"; string(got["etc/ssh/auth_principals/root"].data) != want {
		t.Errorf("auth_principals/root contents: got %q want %q", got["etc/ssh/auth_principals/root"].data, want)
	}

	if string(got["etc/ssh/sshd_config.d/certhold.conf"].data) != sshdConfigContents {
		t.Errorf("sshd_config.d/certhold.conf mismatch:\ngot:\n%s\nwant:\n%s", got["etc/ssh/sshd_config.d/certhold.conf"].data, sshdConfigContents)
	}
	if string(got["etc/ssh/ssh_config.d/certhold.conf"].data) != sshConfigContents {
		t.Errorf("ssh_config.d/certhold.conf mismatch:\ngot:\n%s\nwant:\n%s", got["etc/ssh/ssh_config.d/certhold.conf"].data, sshConfigContents)
	}

	if got["etc/ssh/ca_known_hosts"].data[len(got["etc/ssh/ca_known_hosts"].data)-1] != '\n' {
		t.Errorf("ca_known_hosts not newline-terminated")
	}
	if !strings.HasPrefix(string(got["etc/ssh/ca_known_hosts"].data), "@cert-authority * ssh-ed25519") {
		t.Errorf("ca_known_hosts content: %q", got["etc/ssh/ca_known_hosts"].data)
	}
}

func TestBuild_EmptyKRL(t *testing.T) {
	in := sampleInputs()
	in.KRL = nil
	data, err := Build(in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	got := extract(t, data)
	e, ok := got["etc/ssh/krl"]
	if !ok {
		t.Fatal("krl entry missing")
	}
	if len(e.data) != 0 {
		t.Errorf("krl should be zero bytes, got %d", len(e.data))
	}
}

func TestBuild_EmptyAuthPrincipals(t *testing.T) {
	in := sampleInputs()
	in.AuthPrincipalsRoot = nil
	data, err := Build(in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	got := extract(t, data)
	if string(got["etc/ssh/auth_principals/root"].data) != "manager\n" {
		t.Errorf("auth_principals/root with empty groups: got %q want %q", got["etc/ssh/auth_principals/root"].data, "manager\n")
	}
}

func keys(m map[string]extracted) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
