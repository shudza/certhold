package cli

import (
	"os"
	"strings"
	"testing"
)

func TestHostKeyConfirm_Decision(t *testing.T) {
	const fp = "SHA256:abc123def456"
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"yes accepts", "yes\n", true},
		{"no rejects", "no\n", false},
		{"empty rejects", "\n", false},
		{"eof rejects", "", false},
		{"reprompt then yes", "maybe\nfoo\nyes\n", true},
		{"reprompt then no", "y\nno\n", false},
		{"trailing space yes", "  yes  \n", true},
		{"capital YES not accepted then eof", "YES\n", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := strings.NewReader(tc.input)
			var out strings.Builder
			got, err := hostKeyConfirm(in, &out, "host01", fp, "ED25519", false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %v, want %v (output=%q)", got, tc.want, out.String())
			}
			s := out.String()
			if !strings.Contains(s, "The authenticity of host host01 can't be established.") {
				t.Errorf("missing authenticity line: %q", s)
			}
			if !strings.Contains(s, "ED25519 key fingerprint is "+fp+".") {
				t.Errorf("missing fingerprint line: %q", s)
			}
			if !strings.Contains(s, "Are you sure you want to continue connecting (yes/no)?") {
				t.Errorf("missing confirm prompt: %q", s)
			}
		})
	}
}

func TestHostKeyConfirm_RepromptText(t *testing.T) {
	in := strings.NewReader("garbage\nyes\n")
	var out strings.Builder
	got, err := hostKeyConfirm(in, &out, "h", "SHA256:x", "RSA", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatalf("expected accept after reprompt")
	}
	if !strings.Contains(out.String(), "Please type 'yes' or 'no':") {
		t.Errorf("expected ssh-style reprompt, got %q", out.String())
	}
}

// failReader errors if it is read, proving auto-accept never consumes the tty.
type failReader struct{ t *testing.T }

func (f failReader) Read([]byte) (int, error) {
	f.t.Fatal("reader consumed despite auto-accept")
	return 0, nil
}

func TestHostKeyConfirm_AutoAcceptSkipsReader(t *testing.T) {
	var out strings.Builder
	got, err := hostKeyConfirm(failReader{t}, &out, "h", "SHA256:x", "ED25519", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatalf("auto-accept should return true")
	}
	if out.String() != "" {
		t.Errorf("auto-accept should not write a prompt, got %q", out.String())
	}
}

func TestTrustNewHostKeys(t *testing.T) {
	if !trustNewHostKeys(true) {
		t.Errorf("flag set should auto-accept")
	}
	t.Setenv(envTrustNewHostKeys, "")
	if trustNewHostKeys(false) {
		t.Errorf("no flag, no env should not auto-accept")
	}
	t.Setenv(envTrustNewHostKeys, "1")
	if !trustNewHostKeys(false) {
		t.Errorf("env=1 should auto-accept")
	}
	t.Setenv(envTrustNewHostKeys, "0")
	if trustNewHostKeys(false) {
		t.Errorf("env=0 should not auto-accept")
	}
	t.Setenv(envTrustNewHostKeys, "yes")
	if trustNewHostKeys(false) {
		t.Errorf("env must be exactly 1 to auto-accept")
	}
}

func TestNewHostKeyConfirm_AutoAcceptNoTTY(t *testing.T) {
	// With auto-accept on, the hook must return true without opening /dev/tty
	// (which is absent in CI). Fail-closed when off is covered indirectly: with
	// no tty the OpenFile fails and the hook returns (false, nil).
	hook := newHostKeyConfirm(true)
	ok, err := hook("h", "SHA256:x", "ED25519")
	if err != nil || !ok {
		t.Fatalf("auto-accept hook: ok=%v err=%v", ok, err)
	}
}

func TestNewHostKeyConfirm_FailClosedNoTTY(t *testing.T) {
	if _, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		t.Skip("a controlling tty is present; fail-closed path not exercisable")
	}
	hook := newHostKeyConfirm(false)
	ok, err := hook("h", "SHA256:x", "ED25519")
	if err != nil {
		t.Fatalf("fail-closed should not error: %v", err)
	}
	if ok {
		t.Fatalf("no tty + no auto-accept must reject")
	}
}
