package peerfiles

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestV2SshClientBlockGolden(t *testing.T) {
	const key = "0123456789abcdef"
	want := "# BEGIN certhold 0123456789abcdef v2\n" +
		"# This block is managed by certhold -- auto-generated, do not edit by hand.\n" +
		"# It makes the local ssh client present the certhold-issued certificate\n" +
		"# (CertificateFile + IdentityFile below) on every outbound ssh connection.\n" +
		"# The instance key in the sentinel lines namespaces this block so multiple\n" +
		"# certhold installs can coexist on the same host without clobbering each other.\n" +
		"# To refresh, re-run the enroll one-liner; it idempotently replaces this range.\n" +
		"Host *\n" +
		"    CertificateFile ~/.ssh/id_ed25519_0123456789abcdef-cert.pub\n" +
		"    IdentityFile ~/.ssh/id_ed25519_0123456789abcdef\n" +
		"    UserKnownHostsFile ~/.ssh/known_hosts\n" +
		"# END certhold 0123456789abcdef v2\n"
	if got := V2SshClientBlock(key); got != want {
		t.Errorf("V2SshClientBlock golden mismatch:\ngot:\n%q\nwant:\n%q", got, want)
	}
}

// TestBuildUserZeroValueGolden pins the whole zero-value archive to the sha256
// captured on main before the NoInbound/Hosts/CLIScript/Conf fields landed,
// proving zero values reproduce today's tarball byte-for-byte.
func TestBuildUserZeroValueGolden(t *testing.T) {
	data, err := BuildUser(sampleUserInputs())
	if err != nil {
		t.Fatalf("BuildUser: %v", err)
	}
	sum := sha256.Sum256(data)
	const want = "40590187cc5cea582b6742c16a1f5295dffcc0ad2a52c9feec62c09233bc777d"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Errorf("zero-value BuildUser archive sha256 = %s, want %s (pre-change main)", got, want)
	}
}
