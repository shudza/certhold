package peerfiles

import (
	"regexp"
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

// TestV2SshClientBlockCarriesExplanatoryComments asserts the load-bearing
// phrases that tell a human reading ~/.ssh/config why this block exists.
func TestV2SshClientBlockCarriesExplanatoryComments(t *testing.T) {
	block := V2SshClientBlock("KEY")
	for _, want := range []string{
		"# This block is managed by certhold",
		"do not edit by hand",
		"re-run the enroll one-liner",
		"namespaces this block",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("V2SshClientBlock missing phrase %q\nfull block:\n%s", want, block)
		}
	}
}

// TestV2SshClientBlockFullyScrubbedBySedRange is the re-enrollment invariant:
// the exact regex range used by the install script at
// internal/httpserver/server.go must delete every line of the block, including
// the new explanatory comments. Otherwise re-enrollment would leak stale
// comment lines into ~/.ssh/config.
func TestV2SshClientBlockFullyScrubbedBySedRange(t *testing.T) {
	const key = "KEY"
	beginRe := regexp.MustCompile(`^# BEGIN certhold ` + key + `( v[0-9]+)?$`)
	endRe := regexp.MustCompile(`^# END certhold ` + key + `( v[0-9]+)?$`)

	block := V2SshClientBlock(key)
	lines := strings.Split(block, "\n")

	inRange := false
	var remaining []string
	for _, ln := range lines {
		if !inRange && beginRe.MatchString(ln) {
			inRange = true
			continue
		}
		if inRange {
			if endRe.MatchString(ln) {
				inRange = false
			}
			continue
		}
		remaining = append(remaining, ln)
	}

	for _, ln := range remaining {
		if strings.TrimSpace(ln) != "" {
			t.Errorf("sed-range scrub left non-empty line %q; remaining=%q", ln, remaining)
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
