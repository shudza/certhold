package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootVersionFlag(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })
	Version = "v9.8.7"

	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("--version: %v", err)
	}
	if !strings.Contains(out.String(), "v9.8.7") {
		t.Fatalf("--version output %q does not contain the stamped version", out.String())
	}
}
