package peerfiles

import (
	"strings"
	"testing"
)

func TestStripBlock_RemovesBlockPreservesSurrounding(t *testing.T) {
	const key = "abc123"
	existing := []byte("# user comment\nHost bastion\n    HostName 10.0.0.1\n\n" +
		V2SshClientBlock(key) +
		"Host other\n    HostName 10.0.0.2\n")

	out := StripBlock(existing, key)
	s := string(out)
	if strings.Contains(s, BeginSentinel(key)) || strings.Contains(s, EndSentinel(key)) {
		t.Fatalf("block sentinels still present:\n%s", s)
	}
	if strings.Contains(s, "id_ed25519_"+key) {
		t.Fatalf("block body still present:\n%s", s)
	}
	for _, must := range []string{"# user comment", "Host bastion", "HostName 10.0.0.1", "Host other", "HostName 10.0.0.2"} {
		if !strings.Contains(s, must) {
			t.Errorf("surrounding config %q was dropped:\n%s", must, s)
		}
	}
}

func TestStripBlock_NoOpWhenAbsent(t *testing.T) {
	existing := []byte("# just user config\nHost foo\n    HostName 1.2.3.4\n")
	out := StripBlock(existing, "abc123")
	if string(out) != string(existing) {
		t.Errorf("expected unchanged input, got:\n%s", out)
	}
}

func TestStripBlock_LegacyVersionSuffix(t *testing.T) {
	const key = "abc123"
	existing := []byte("before\n" +
		"# BEGIN certhold " + key + " v1\nIdentityFile ~/.ssh/old\n# END certhold " + key + " v1\n" +
		"after\n")
	out := StripBlock(existing, key)
	s := string(out)
	if strings.Contains(s, "certhold "+key) {
		t.Fatalf("legacy v1 block not removed:\n%s", s)
	}
	if !strings.Contains(s, "before") || !strings.Contains(s, "after") {
		t.Fatalf("surrounding content dropped:\n%s", s)
	}
}

func TestStripBlock_NoVersionSuffix(t *testing.T) {
	const key = "abc123"
	existing := []byte("# BEGIN certhold " + key + "\nbody\n# END certhold " + key + "\n")
	out := StripBlock(existing, key)
	if strings.TrimSpace(string(out)) != "" {
		t.Fatalf("expected empty output, got:\n%s", out)
	}
}

func TestStripBlock_OnlyTheBlock(t *testing.T) {
	const key = "abc123"
	existing := []byte(V2SshClientBlock(key))
	out := StripBlock(existing, key)
	if strings.TrimSpace(string(out)) != "" {
		t.Fatalf("file that was only the block should become empty, got:\n%q", out)
	}
}

func TestStripBlock_OnlyMatchingKey(t *testing.T) {
	mine := "mine"
	other := "other"
	existing := []byte(V2SshClientBlock(mine) + V2SshClientBlock(other))
	out := StripBlock(existing, mine)
	s := string(out)
	if strings.Contains(s, BeginSentinel(mine)) {
		t.Fatalf("own block not removed:\n%s", s)
	}
	if !strings.Contains(s, BeginSentinel(other)) {
		t.Fatalf("foreign instance block was removed:\n%s", s)
	}
}

func TestStripCALine_RemovesOnlyMatching(t *testing.T) {
	caPub, caAK := newTestCAKey(t)
	otherPub, otherAK := newTestCAKey(t)
	caTrim := strings.TrimRight(string(caAK), "\n")
	otherTrim := strings.TrimRight(string(otherAK), "\n")

	existing := []byte("# header\n" +
		"cert-authority,principals=\"manager,web\" " + caTrim + "\n" +
		"cert-authority,principals=\"manager\" " + otherTrim + "\n" +
		"ssh-ed25519 AAAAplainuserkey user@host\n")

	out := StripCALine(existing, caPub)
	s := string(out)
	if strings.Contains(s, caTrim) {
		t.Fatalf("matching cert-authority line not removed:\n%s", s)
	}
	if !strings.Contains(s, otherTrim) {
		t.Fatalf("non-matching cert-authority line was dropped:\n%s", s)
	}
	for _, must := range []string{"# header", "ssh-ed25519 AAAAplainuserkey user@host"} {
		if !strings.Contains(s, must) {
			t.Errorf("preserved line %q dropped:\n%s", must, s)
		}
	}
	_ = otherPub
}

// TestStripCALine_MultipleKeysPreservesForeign models a straggler revoke: the
// peer carries lines for this instance's active AND archived old CA plus a
// foreign instance's line; one pass with both of our keys removes ours only.
func TestStripCALine_MultipleKeysPreservesForeign(t *testing.T) {
	activePub, activeAK := newTestCAKey(t)
	archivedPub, archivedAK := newTestCAKey(t)
	_, foreignAK := newTestCAKey(t)
	activeTrim := strings.TrimRight(string(activeAK), "\n")
	archivedTrim := strings.TrimRight(string(archivedAK), "\n")
	foreignTrim := strings.TrimRight(string(foreignAK), "\n")

	existing := []byte("# header\n" +
		"cert-authority,principals=\"manager,web\" " + activeTrim + "\n" +
		"cert-authority,principals=\"manager,web\" " + archivedTrim + "\n" +
		"cert-authority,principals=\"manager\" " + foreignTrim + "\n" +
		"ssh-ed25519 AAAAplainuserkey user@host\n")

	out := StripCALine(existing, activePub, archivedPub)
	s := string(out)
	if strings.Contains(s, activeTrim) {
		t.Fatalf("active-CA line not removed:\n%s", s)
	}
	if strings.Contains(s, archivedTrim) {
		t.Fatalf("archived-old-CA line not removed:\n%s", s)
	}
	if !strings.Contains(s, foreignTrim) {
		t.Fatalf("foreign instance's line was dropped:\n%s", s)
	}
	for _, must := range []string{"# header", "ssh-ed25519 AAAAplainuserkey user@host"} {
		if !strings.Contains(s, must) {
			t.Errorf("preserved line %q dropped:\n%s", must, s)
		}
	}
}

func TestStripCALine_NoOpWhenAbsent(t *testing.T) {
	caPub, _ := newTestCAKey(t)
	otherPub, otherAK := newTestCAKey(t)
	otherTrim := strings.TrimRight(string(otherAK), "\n")
	existing := []byte("# header\ncert-authority,principals=\"manager\" " + otherTrim + "\nssh-ed25519 AAAAuser u@h\n")

	out := StripCALine(existing, caPub)
	if string(out) != string(existing) {
		t.Errorf("expected unchanged input when no matching CA line, got:\n%s", out)
	}
	_ = otherPub
}
