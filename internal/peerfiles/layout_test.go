package peerfiles

import (
	"strings"
	"testing"
)

// Pre-PR1 block bodies (between the sentinels). PR1 must keep these byte-identical;
// only the sentinel lines gain a v1 suffix.
const legacySshdBody = `HostKey /etc/ssh/peer_ed25519
HostCertificate /etc/ssh/peer_ed25519-cert.pub
TrustedUserCAKeys /etc/ssh/ca.pub
RevokedKeys /etc/ssh/krl
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
`

const legacySshClientBody = `Host *
    CertificateFile /etc/ssh/peer_ed25519-cert.pub
    IdentityFile /etc/ssh/peer_ed25519
    UserKnownHostsFile /etc/ssh/ca_known_hosts
`

func TestSentinelsAreVersioned(t *testing.T) {
	if got := BeginSentinel(LayoutV1); got != "# BEGIN certhold v1" {
		t.Errorf("BeginSentinel(v1) = %q, want %q", got, "# BEGIN certhold v1")
	}
	if got := EndSentinel(LayoutV1); got != "# END certhold v1" {
		t.Errorf("EndSentinel(v1) = %q, want %q", got, "# END certhold v1")
	}
}

func bodyBetweenSentinels(t *testing.T, block string) string {
	t.Helper()
	begin := "# BEGIN certhold v1\n"
	end := "\n# END certhold v1\n"
	bi := strings.Index(block, begin)
	if bi != 0 {
		t.Fatalf("block does not start with %q: %q", begin, block)
	}
	ei := strings.Index(block, end)
	if ei < 0 {
		t.Fatalf("block missing end sentinel %q: %q", end, block)
	}
	return block[len(begin):ei] + "\n"
}

func TestSshdBlockV1(t *testing.T) {
	block := SshdBlock(LayoutV1)
	if !strings.Contains(block, "# BEGIN certhold v1") {
		t.Errorf("SshdBlock(v1) missing begin sentinel: %q", block)
	}
	if !strings.Contains(block, "# END certhold v1") {
		t.Errorf("SshdBlock(v1) missing end sentinel: %q", block)
	}
	if got := bodyBetweenSentinels(t, block); got != legacySshdBody {
		t.Errorf("SshdBlock(v1) body changed:\ngot:\n%q\nwant:\n%q", got, legacySshdBody)
	}
}

func TestSshClientBlockV1(t *testing.T) {
	block := SshClientBlock(LayoutV1)
	if !strings.Contains(block, "# BEGIN certhold v1") {
		t.Errorf("SshClientBlock(v1) missing begin sentinel: %q", block)
	}
	if !strings.Contains(block, "# END certhold v1") {
		t.Errorf("SshClientBlock(v1) missing end sentinel: %q", block)
	}
	if got := bodyBetweenSentinels(t, block); got != legacySshClientBody {
		t.Errorf("SshClientBlock(v1) body changed:\ngot:\n%q\nwant:\n%q", got, legacySshClientBody)
	}
}

func TestPathsForRootV1(t *testing.T) {
	p := PathsFor(LayoutV1, "root", "", "")
	want := RemotePaths{
		Cert:           "/etc/ssh/peer_ed25519-cert.pub",
		AuthorizedKeys: "/etc/ssh/auth_principals/root",
		CAPub:          "/etc/ssh/ca.pub",
		KRL:            "/etc/ssh/krl",
		KnownHosts:     "/etc/ssh/ca_known_hosts",
		ConfigTarget:   "/etc/ssh/sshd_config",
	}
	if p != want {
		t.Errorf("PathsFor root v1 = %+v, want %+v", p, want)
	}
}

// TestTarballBodiesCarryNoSentinels is the no-op proof: the v1 tarball file
// bodies (root-mode Build and user-mode BuildUser) never contain the splice
// sentinels, so versioning the sentinels leaves both tarballs byte-identical.
func TestTarballBodiesCarryNoSentinels(t *testing.T) {
	root, err := Build(sampleInputs())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	user, err := BuildUser(sampleUserInputs())
	if err != nil {
		t.Fatalf("BuildUser: %v", err)
	}
	for label, files := range map[string]map[string]extracted{
		"Build":     extract(t, root),
		"BuildUser": extractUser(t, user),
	} {
		for name, e := range files {
			if strings.Contains(string(e.data), "certhold v") || strings.Contains(string(e.data), "BEGIN certhold") {
				t.Errorf("%s file %q unexpectedly carries a sentinel: %q", label, name, e.data)
			}
		}
	}
}

func TestPathsForUserV1(t *testing.T) {
	p := PathsFor(LayoutV1, "user", "alice", "")
	want := RemotePaths{
		Cert:           "/home/alice/.ssh/id_ed25519-cert.pub",
		AuthorizedKeys: "/home/alice/.ssh/authorized_keys",
		CAPub:          "/home/alice/.ssh/ca.pub",
		KRL:            "/home/alice/.ssh/krl",
		KnownHosts:     "/home/alice/.ssh/known_hosts",
		ConfigTarget:   "/home/alice/.ssh/config",
	}
	if p != want {
		t.Errorf("PathsFor user v1 = %+v, want %+v", p, want)
	}
}
