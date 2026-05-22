package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/shudza/certhold/internal/cli"
)

func TestRootHelpListsSubcommands(t *testing.T) {
	cmd := cli.NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	got := out.String()
	for _, name := range []string{"init", "enroll", "list", "update", "group", "revoke", "rekey"} {
		if !strings.Contains(got, name) {
			t.Errorf("help output missing subcommand %q\nfull output:\n%s", name, got)
		}
	}
}
