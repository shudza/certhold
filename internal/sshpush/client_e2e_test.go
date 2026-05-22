//go:build e2e

package sshpush

import (
	"os"
	"testing"
)

// TestE2E is a placeholder for the real end-to-end integration test that
// drives sshpush against an actual sshd instance.
//
// To run:
//
//	1. Stand up an OpenSSH server (the typical setup uses a docker container,
//	   e.g. `linuxserver/openssh-server`, with TrustedUserCAKeys pointed at a
//	   throwaway CA the test generates).
//	2. Generate a peer key+cert with internal/ca, populate the container's
//	   /etc/ssh/auth_principals/root with the certhold principal, and capture
//	   the container's host key into a known_hosts file.
//	3. Export CERTHOLD_E2E=1 and the container's address (e.g.
//	   CERTHOLD_E2E_HOST=127.0.0.1:2222) before running:
//	     CERTHOLD_E2E=1 go test -tags=e2e -run TestE2E ./internal/sshpush/...
//
// The build tag and the env var guard are belt-and-suspenders: even when
// compiled in, the test exits cleanly if CERTHOLD_E2E is unset so CI runs
// don't accidentally trigger it.
func TestE2E(t *testing.T) {
	if os.Getenv("CERTHOLD_E2E") != "1" {
		t.Skip("E2E placeholder: set CERTHOLD_E2E=1 and supply a real sshd target to enable")
	}
	t.Skip("E2E placeholder: real sshd target wiring not yet implemented")
}
