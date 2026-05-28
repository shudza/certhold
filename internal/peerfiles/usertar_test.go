package peerfiles

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testInstanceKey = "0123456789abcdef"

func sampleUserInputs() UserPeerFiles {
	return UserPeerFiles{
		TargetUser:  "root",
		PrivKey:     []byte("PRIV"),
		CertPub:     []byte("CERT"),
		CAPub:       []byte("ssh-ed25519 AAAATEST certhold-ca\n"),
		Principals:  []string{"infra", "databases"},
		InstanceKey: testInstanceKey,
	}
}

type extracted struct {
	mode int64
	data []byte
}

func extractUser(t *testing.T, archive []byte) map[string]extracted {
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
			t.Fatalf("tar: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		out[hdr.Name] = extracted{mode: hdr.Mode, data: data}
	}
	return out
}

func keys(m map[string]extracted) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestBuildUser_NamespacedEntries(t *testing.T) {
	in := sampleUserInputs()
	data, err := BuildUser(in)
	if err != nil {
		t.Fatalf("BuildUser: %v", err)
	}
	got := extractUser(t, data)
	want := map[string]int64{
		"id_ed25519_" + in.InstanceKey:               0600,
		"id_ed25519_" + in.InstanceKey + "-cert.pub": 0644,
		"known_hosts":        0644,
		"config":             0644,
		"ca_authorized_keys": 0644,
	}
	if len(got) != len(want) {
		t.Fatalf("entry count: got %d want %d: %v", len(got), len(want), keys(got))
	}
	for name, mode := range want {
		e, ok := got[name]
		if !ok {
			t.Errorf("missing %q; have %v", name, keys(got))
			continue
		}
		if e.mode != mode {
			t.Errorf("%s mode: got %o want %o", name, e.mode, mode)
		}
	}
	// v2 must NOT ship a whole authorized_keys file (install appends the line).
	if _, ok := got["authorized_keys"]; ok {
		t.Errorf("tarball must not ship a whole authorized_keys file")
	}
	for n := range got {
		if strings.HasPrefix(n, "/") || strings.HasPrefix(n, "etc/") {
			t.Errorf("user-mode entry has root path %q", n)
		}
	}
}

func TestBuildUser_CALineDedupedManagerFirst(t *testing.T) {
	in := sampleUserInputs()
	in.Principals = []string{"manager", "infra", "infra", "databases"}
	data, err := BuildUser(in)
	if err != nil {
		t.Fatalf("BuildUser: %v", err)
	}
	got := extractUser(t, data)
	ak := string(got["ca_authorized_keys"].data)
	wantLine := `cert-authority,principals="manager,infra,databases" ssh-ed25519 AAAATEST certhold-ca` + "\n"
	if ak != wantLine {
		t.Errorf("ca_authorized_keys = %q\nwant %q", ak, wantLine)
	}
}

func TestBuildUser_EmptyKnownHosts(t *testing.T) {
	data, err := BuildUser(sampleUserInputs())
	if err != nil {
		t.Fatalf("BuildUser: %v", err)
	}
	got := extractUser(t, data)
	kh, ok := got["known_hosts"]
	if !ok {
		t.Fatal("known_hosts missing")
	}
	if len(kh.data) != 0 {
		t.Errorf("known_hosts should be empty, got %d bytes", len(kh.data))
	}
}

func TestBuildUser_NamespacedIdentityAndConfig(t *testing.T) {
	in := sampleUserInputs()
	data, err := BuildUser(in)
	if err != nil {
		t.Fatalf("BuildUser: %v", err)
	}
	got := extractUser(t, data)

	if _, ok := got["id_ed25519_"+in.InstanceKey]; !ok {
		t.Errorf("missing namespaced private key entry; have %v", keys(got))
	}
	if _, ok := got["id_ed25519_"+in.InstanceKey+"-cert.pub"]; !ok {
		t.Errorf("missing namespaced cert entry; have %v", keys(got))
	}
	caLine, ok := got["ca_authorized_keys"]
	if !ok {
		t.Fatalf("missing ca_authorized_keys line entry; have %v", keys(got))
	}
	wantLine := `cert-authority,principals="manager,infra,databases" ssh-ed25519 AAAATEST certhold-ca` + "\n"
	if string(caLine.data) != wantLine {
		t.Errorf("ca_authorized_keys = %q, want %q", caLine.data, wantLine)
	}
	// No global sshd directives, no auth_principals/root anywhere in the set.
	for name, e := range got {
		s := string(e.data)
		for _, forbidden := range []string{"TrustedUserCAKeys", "AuthorizedPrincipalsFile", "RevokedKeys", "HostCertificate", "auth_principals/root"} {
			if strings.Contains(s, forbidden) {
				t.Errorf("entry %q unexpectedly contains %q", name, forbidden)
			}
		}
	}
	cfg := string(got["config"].data)
	for _, must := range []string{
		"# BEGIN certhold " + in.InstanceKey + " v2",
		"CertificateFile ~/.ssh/id_ed25519_" + in.InstanceKey + "-cert.pub",
		"IdentityFile ~/.ssh/id_ed25519_" + in.InstanceKey,
		"# END certhold " + in.InstanceKey + " v2",
	} {
		if !strings.Contains(cfg, must) {
			t.Errorf("config missing %q\nfull:\n%s", must, cfg)
		}
	}
}

func TestWriteUserSelfFiles(t *testing.T) {
	dir := t.TempDir()
	in := sampleUserInputs()
	in.TargetUser = "alice"
	if err := WriteUserSelfFiles(dir, in); err != nil {
		t.Fatalf("WriteUserSelfFiles: %v", err)
	}
	base := filepath.Join(dir, "home", "alice", ".ssh")
	for name, mode := range map[string]os.FileMode{
		"id_ed25519_" + in.InstanceKey:               0600,
		"id_ed25519_" + in.InstanceKey + "-cert.pub": 0644,
		"authorized_keys":                            0644,
		"known_hosts":                                0644,
		"config":                                     0644,
	} {
		full := filepath.Join(base, name)
		st, err := os.Stat(full)
		if err != nil {
			t.Errorf("stat %s: %v", name, err)
			continue
		}
		if st.Mode().Perm() != mode {
			t.Errorf("%s mode: got %o want %o", name, st.Mode().Perm(), mode)
		}
	}
	ak, err := os.ReadFile(filepath.Join(base, "authorized_keys"))
	if err != nil {
		t.Fatalf("read authorized_keys: %v", err)
	}
	wantPrefix := `cert-authority,principals="manager,`
	if !strings.HasPrefix(string(ak), wantPrefix) {
		t.Errorf("authorized_keys prefix wrong: %q", ak)
	}
	// The self mirror materializes authorized_keys rather than shipping the
	// install-time ca_authorized_keys append.
	if _, err := os.Stat(filepath.Join(base, "ca_authorized_keys")); err == nil {
		t.Errorf("self mirror must not write ca_authorized_keys")
	}
}

func TestWriteUserSelfFilesRootGoesUnderRoot(t *testing.T) {
	dir := t.TempDir()
	in := sampleUserInputs()
	in.TargetUser = "root"
	if err := WriteUserSelfFiles(dir, in); err != nil {
		t.Fatalf("WriteUserSelfFiles: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "root", ".ssh", "id_ed25519_"+in.InstanceKey)); err != nil {
		t.Errorf("expected files under <dir>/root/.ssh/ for target_user=root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "home", "root", ".ssh", "id_ed25519_"+in.InstanceKey)); err == nil {
		t.Errorf("must not write under <dir>/home/root/.ssh/ for target_user=root")
	}
}
