package peerfiles

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func newTestCAKey(t *testing.T) (ssh.PublicKey, []byte) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	return sshPub, ssh.MarshalAuthorizedKey(sshPub)
}

func TestRewritePrincipals_HappyPath(t *testing.T) {
	caPub, caAK := newTestCAKey(t)
	caTrim := strings.TrimRight(string(caAK), "\n")
	existing := []byte(`# header
some-other-line ssh-ed25519 AAAAfoo
cert-authority,principals="manager,old" ` + caTrim + `
trailing comment line
`)

	out, err := RewritePrincipals(existing, caPub, []string{"infra", "databases"})
	if err != nil {
		t.Fatalf("RewritePrincipals: %v", err)
	}

	s := string(out)
	wantLine := `cert-authority,principals="manager,infra,databases" ` + caTrim
	if !strings.Contains(s, wantLine) {
		t.Errorf("output missing rewritten line %q\nfull:\n%s", wantLine, s)
	}
	for _, must := range []string{"# header", "some-other-line ssh-ed25519 AAAAfoo", "trailing comment line"} {
		if !strings.Contains(s, must) {
			t.Errorf("output missing preserved line %q\nfull:\n%s", must, s)
		}
	}
	if strings.Contains(s, `principals="manager,old"`) {
		t.Errorf("old principals should be replaced\nfull:\n%s", s)
	}
}

func TestRewritePrincipals_ManagerAlwaysPrepended(t *testing.T) {
	caPub, caAK := newTestCAKey(t)
	caTrim := strings.TrimRight(string(caAK), "\n")
	existing := []byte(`cert-authority,principals="manager,old" ` + caTrim + "\n")

	out, err := RewritePrincipals(existing, caPub, []string{"infra"})
	if err != nil {
		t.Fatalf("RewritePrincipals: %v", err)
	}
	want := `cert-authority,principals="manager,infra" ` + caTrim
	if !strings.Contains(string(out), want) {
		t.Errorf("want %q in:\n%s", want, out)
	}
}

func TestRewritePrincipals_MultipleCALinesOnlyMatching(t *testing.T) {
	caPub, caAK := newTestCAKey(t)
	otherPub, otherAK := newTestCAKey(t)
	caTrim := strings.TrimRight(string(caAK), "\n")
	otherTrim := strings.TrimRight(string(otherAK), "\n")

	existing := []byte(`cert-authority,principals="manager,old" ` + caTrim + `
cert-authority,principals="manager,other-other" ` + otherTrim + `
`)

	out, err := RewritePrincipals(existing, caPub, []string{"infra"})
	if err != nil {
		t.Fatalf("RewritePrincipals: %v", err)
	}
	s := string(out)
	wantNew := `cert-authority,principals="manager,infra" ` + caTrim
	wantOld := `cert-authority,principals="manager,other-other" ` + otherTrim
	if !strings.Contains(s, wantNew) {
		t.Errorf("missing rewritten line for matching CA\nout:\n%s", s)
	}
	if !strings.Contains(s, wantOld) {
		t.Errorf("non-matching CA line was modified\nout:\n%s", s)
	}
	_ = otherPub
}

func TestRewritePrincipals_NoMatchingLine(t *testing.T) {
	caPub, _ := newTestCAKey(t)
	_, otherAK := newTestCAKey(t)
	otherTrim := strings.TrimRight(string(otherAK), "\n")
	existing := []byte(`cert-authority,principals="manager,x" ` + otherTrim + "\n")
	_, err := RewritePrincipals(existing, caPub, []string{"a"})
	if !errors.Is(err, ErrNoMatchingLine) {
		t.Errorf("expected ErrNoMatchingLine, got %v", err)
	}
}

func TestRewritePrincipals_PreservesLineOrder(t *testing.T) {
	caPub, caAK := newTestCAKey(t)
	caTrim := strings.TrimRight(string(caAK), "\n")
	existing := []byte("# top\n" +
		"ssh-ed25519 AAAAfoo extra\n" +
		`cert-authority,principals="manager,old" ` + caTrim + "\n" +
		"# bottom\n")
	out, err := RewritePrincipals(existing, caPub, []string{"infra"})
	if err != nil {
		t.Fatalf("RewritePrincipals: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("got %d lines, want 4: %q", len(lines), lines)
	}
	if lines[0] != "# top" || lines[1] != "ssh-ed25519 AAAAfoo extra" || lines[3] != "# bottom" {
		t.Errorf("line order changed: %q", lines)
	}
	if !strings.HasPrefix(lines[2], `cert-authority,principals="manager,infra"`) {
		t.Errorf("rewritten line wrong: %q", lines[2])
	}
}

func TestReplaceCALine_PreservesOtherInstances(t *testing.T) {
	caA, caAAK := newTestCAKey(t)
	caB, caBAK := newTestCAKey(t)
	_ = caB
	caATrim := strings.TrimRight(string(caAAK), "\n")
	caBTrim := strings.TrimRight(string(caBAK), "\n")

	// authorized_keys with two instances' lines (A and B).
	existing := []byte(`# header
cert-authority,principals="manager,infra" ` + caATrim + `
cert-authority,principals="manager,db" ` + caBTrim + `
`)

	// Rotate instance A's CA to caB-shaped new line (simulated): produce a new
	// line whose key differs from the old caA. Reuse caB's bytes as the "new"
	// key for A — the test only checks that A's old line is swapped and B's
	// line (matched by its own CA) is untouched.
	newCAPub, newCAAK := newTestCAKey(t)
	_ = newCAPub
	newLine := []byte(`cert-authority,principals="manager,infra" ` + strings.TrimRight(string(newCAAK), "\n") + "\n")

	out := ReplaceCALine(existing, caA, newLine)
	s := string(out)
	if strings.Contains(s, caATrim) {
		t.Errorf("old CA-A line should have been replaced:\n%s", s)
	}
	if !strings.Contains(s, strings.TrimRight(string(newCAAK), "\n")) {
		t.Errorf("new CA-A line missing:\n%s", s)
	}
	if !strings.Contains(s, caBTrim) {
		t.Errorf("other instance (CA-B) line must be preserved:\n%s", s)
	}
	if !strings.Contains(s, "# header") {
		t.Errorf("comment line must be preserved:\n%s", s)
	}
}

func TestReplaceCALine_AppendsWhenAbsent(t *testing.T) {
	caA, caAAK := newTestCAKey(t)
	existing := []byte("# only a comment\n")
	newLine := []byte(`cert-authority,principals="manager" ` + strings.TrimRight(string(caAAK), "\n") + "\n")
	_ = caA
	out := ReplaceCALine(existing, caA, newLine)
	if !strings.Contains(string(out), strings.TrimRight(string(caAAK), "\n")) {
		t.Errorf("new line should be appended when no match:\n%s", out)
	}
	if !strings.Contains(string(out), "# only a comment") {
		t.Errorf("existing content must be preserved:\n%s", out)
	}
}
