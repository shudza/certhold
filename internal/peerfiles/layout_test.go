package peerfiles

import (
	"strings"
	"testing"
)

func TestSentinelsCarryKey(t *testing.T) {
	const key = "0123456789abcdef"
	if got, want := BeginSentinel(key), "# BEGIN certhold "+key+" v2"; got != want {
		t.Errorf("BeginSentinel = %q, want %q", got, want)
	}
	if got, want := EndSentinel(key), "# END certhold "+key+" v2"; got != want {
		t.Errorf("EndSentinel = %q, want %q", got, want)
	}
}

func TestPathsForRoot(t *testing.T) {
	const key = "0123456789abcdef"
	p := PathsFor("", key)
	if p.Cert != "/root/.ssh/id_ed25519_"+key+"-cert.pub" {
		t.Errorf("root Cert = %q", p.Cert)
	}
	if p.AuthorizedKeys != "/root/.ssh/authorized_keys" {
		t.Errorf("root AuthorizedKeys = %q", p.AuthorizedKeys)
	}
	if p.ConfigTarget != "/root/.ssh/config" {
		t.Errorf("root ConfigTarget = %q", p.ConfigTarget)
	}
	if p.KRL != "" {
		t.Errorf("must have no KRL, got %q", p.KRL)
	}
	if strings.Contains(p.AuthorizedKeys, "auth_principals") {
		t.Errorf("must not use auth_principals: %q", p.AuthorizedKeys)
	}
}

func TestPathsForUser(t *testing.T) {
	const key = "0123456789abcdef"
	p := PathsFor("alice", key)
	if p.Cert != "/home/alice/.ssh/id_ed25519_"+key+"-cert.pub" {
		t.Errorf("user Cert = %q", p.Cert)
	}
	if p.AuthorizedKeys != "/home/alice/.ssh/authorized_keys" {
		t.Errorf("user AuthorizedKeys = %q", p.AuthorizedKeys)
	}
}

// TestPathsForNoEtcSsh asserts the collapsed layout never produces /etc/ssh
// paths for any target user.
func TestPathsForNoEtcSsh(t *testing.T) {
	for _, user := range []string{"", "root", "alice"} {
		p := PathsFor(user, "0123456789abcdef")
		for _, path := range []string{p.Cert, p.AuthorizedKeys, p.CAPub, p.KRL, p.KnownHosts, p.ConfigTarget} {
			if strings.Contains(path, "/etc/ssh") {
				t.Errorf("PathsFor(%q) produced /etc/ssh path: %q", user, path)
			}
		}
	}
}

// TestTarballBodiesCarryNoSplittableSentinels is the no-op proof: the BuildUser
// tarball's known_hosts and identity files never contain the splice sentinels,
// so only the config carries them (asserted by the usertar tests).
func TestTarballBodiesCarryNoSentinels(t *testing.T) {
	user, err := BuildUser(sampleUserInputs())
	if err != nil {
		t.Fatalf("BuildUser: %v", err)
	}
	for name, e := range extractUser(t, user) {
		if name == "config" {
			continue
		}
		if strings.Contains(string(e.data), "certhold ") || strings.Contains(string(e.data), "BEGIN certhold") {
			t.Errorf("BuildUser file %q unexpectedly carries a sentinel: %q", name, e.data)
		}
	}
}
