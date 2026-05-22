package peerfiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteSelfFiles_AllEntriesAndModes(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "self")
	if err := WriteSelfFiles(root, sampleInputs()); err != nil {
		t.Fatalf("WriteSelfFiles: %v", err)
	}

	expected := map[string]os.FileMode{
		"etc/ssh/peer_ed25519":           0600,
		"etc/ssh/peer_ed25519-cert.pub":  0644,
		"etc/ssh/ca.pub":                 0644,
		"etc/ssh/krl":                    0644,
		"etc/ssh/auth_principals/root":   0644,
		"etc/ssh/ca_known_hosts":         0644,
		"etc/ssh/sshd_config_block.conf": 0644,
		"etc/ssh/ssh_config_block.conf":  0644,
	}

	for name, mode := range expected {
		full := filepath.Join(root, name)
		st, err := os.Stat(full)
		if err != nil {
			t.Errorf("stat %s: %v", name, err)
			continue
		}
		if st.Mode().Perm() != mode {
			t.Errorf("%s mode: got %o want %o", name, st.Mode().Perm(), mode)
		}
	}

	for _, forbidden := range []string{
		"etc/ssh/sshd_config.d/certhold.conf",
		"etc/ssh/ssh_config.d/certhold.conf",
	} {
		if _, err := os.Stat(filepath.Join(root, forbidden)); !os.IsNotExist(err) {
			t.Errorf("forbidden file present: %q (err=%v)", forbidden, err)
		}
	}

	sshdBlock, err := os.ReadFile(filepath.Join(root, "etc/ssh/sshd_config_block.conf"))
	if err != nil {
		t.Fatalf("read sshd_config_block.conf: %v", err)
	}
	if string(sshdBlock) != SshdBlockContents {
		t.Errorf("sshd_config_block.conf mismatch:\ngot:\n%s\nwant:\n%s", sshdBlock, SshdBlockContents)
	}
	if !strings.Contains(string(sshdBlock), "# BEGIN certhold\n") || !strings.Contains(string(sshdBlock), "\n# END certhold\n") {
		t.Errorf("sshd_config_block.conf missing sentinels: %q", sshdBlock)
	}

	sshBlock, err := os.ReadFile(filepath.Join(root, "etc/ssh/ssh_config_block.conf"))
	if err != nil {
		t.Fatalf("read ssh_config_block.conf: %v", err)
	}
	if string(sshBlock) != SshClientBlockContents {
		t.Errorf("ssh_config_block.conf mismatch:\ngot:\n%s\nwant:\n%s", sshBlock, SshClientBlockContents)
	}
	if !strings.Contains(string(sshBlock), "# BEGIN certhold\n") || !strings.Contains(string(sshBlock), "\n# END certhold\n") {
		t.Errorf("ssh_config_block.conf missing sentinels: %q", sshBlock)
	}

	rootStat, err := os.Stat(root)
	if err != nil {
		t.Fatalf("stat root: %v", err)
	}
	if rootStat.Mode().Perm() != 0700 {
		t.Errorf("root dir mode: got %o want 0700", rootStat.Mode().Perm())
	}

	authData, err := os.ReadFile(filepath.Join(root, "etc/ssh/auth_principals/root"))
	if err != nil {
		t.Fatalf("read auth_principals/root: %v", err)
	}
	if want := "manager\ninfra\ndatabases\n"; string(authData) != want {
		t.Errorf("auth_principals/root: got %q want %q", authData, want)
	}

	caKH, err := os.ReadFile(filepath.Join(root, "etc/ssh/ca_known_hosts"))
	if err != nil {
		t.Fatalf("read ca_known_hosts: %v", err)
	}
	if caKH[len(caKH)-1] != '\n' {
		t.Errorf("ca_known_hosts not newline-terminated")
	}
}

func TestWriteSelfFiles_EmptyKRL(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "self")
	in := sampleInputs()
	in.KRL = nil
	if err := WriteSelfFiles(root, in); err != nil {
		t.Fatalf("WriteSelfFiles: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "etc/ssh/krl"))
	if err != nil {
		t.Fatalf("read krl: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("krl should be zero bytes, got %d", len(data))
	}
}

func TestWriteSelfFiles_EmptyAuthPrincipals(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "self")
	in := sampleInputs()
	in.AuthPrincipalsRoot = nil
	if err := WriteSelfFiles(root, in); err != nil {
		t.Fatalf("WriteSelfFiles: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "etc/ssh/auth_principals/root"))
	if err != nil {
		t.Fatalf("read auth_principals/root: %v", err)
	}
	if string(data) != "manager\n" {
		t.Errorf("auth_principals/root: got %q want %q", data, "manager\n")
	}
}
