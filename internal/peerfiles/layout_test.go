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

func TestV2SshClientBlockWithHostsNilMatchesPlainBlock(t *testing.T) {
	const key = "0123456789abcdef"
	if got, want := V2SshClientBlockWithHosts(key, nil), V2SshClientBlock(key); got != want {
		t.Errorf("nil-hosts block differs from V2SshClientBlock:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestV2SshClientBlockWithHostsEmittedBeforeHostStar(t *testing.T) {
	const key = "0123456789abcdef"
	block := V2SshClientBlockWithHosts(key, []HostEntry{
		{Name: "web1", Address: "10.0.0.1", User: "deploy"},
		{Name: "db1", Address: "10.0.0.2"},
	})
	begin := strings.Index(block, BeginSentinel(key))
	web1 := strings.Index(block, "Host web1\n")
	db1 := strings.Index(block, "Host db1\n")
	star := strings.Index(block, "Host *\n")
	end := strings.Index(block, EndSentinel(key))
	if begin < 0 || web1 < 0 || db1 < 0 || star < 0 || end < 0 {
		t.Fatalf("missing stanza markers (begin=%d web1=%d db1=%d star=%d end=%d):\n%s", begin, web1, db1, star, end, block)
	}
	if !(begin < web1 && web1 < db1 && db1 < star && star < end) {
		t.Errorf("host stanzas not between begin sentinel and Host * (begin=%d web1=%d db1=%d star=%d end=%d):\n%s", begin, web1, db1, star, end, block)
	}
}

func TestV2SshClientBlockWithHostsConditionalLines(t *testing.T) {
	const key = "0123456789abcdef"
	block := V2SshClientBlockWithHosts(key, []HostEntry{
		{Name: "full", Address: "192.0.2.1", User: "alice"},
		{Name: "addr-only", Address: "192.0.2.2"},
		{Name: "user-only", User: "bob"},
	})
	if !strings.Contains(block, "Host full\n    HostName 192.0.2.1\n    User alice\n") {
		t.Errorf("full entry stanza wrong:\n%s", block)
	}
	if !strings.Contains(block, "Host addr-only\n    HostName 192.0.2.2\nHost user-only\n    User bob\n") {
		t.Errorf("conditional HostName/User lines wrong:\n%s", block)
	}
}

func TestV2SshClientBlockWithHostsSkipsEmptyEntry(t *testing.T) {
	const key = "0123456789abcdef"
	block := V2SshClientBlockWithHosts(key, []HostEntry{
		{Name: "ghost"},
		{Name: "real", Address: "192.0.2.9"},
	})
	if strings.Contains(block, "Host ghost") {
		t.Errorf("entry with empty Address and User must be skipped:\n%s", block)
	}
	if !strings.Contains(block, "Host real\n") {
		t.Errorf("non-empty entry missing:\n%s", block)
	}
}

func TestV2SshClientBlockWithHostsFullyScrubbedBySedRange(t *testing.T) {
	const key = "KEY"
	beginRe := regexp.MustCompile(`^# BEGIN certhold ` + key + `( v[0-9]+)?$`)
	endRe := regexp.MustCompile(`^# END certhold ` + key + `( v[0-9]+)?$`)

	block := V2SshClientBlockWithHosts(key, []HostEntry{{Name: "web1", Address: "10.0.0.1", User: "deploy"}})
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
