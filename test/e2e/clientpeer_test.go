//go:build e2e

// Client-peer e2e flow (issue #97): enroll a host-style peer (app01 @ peer4)
// and a client-style peer (laptop @ peer5, `enroll --client`), then drive the
// whole pull-channel story end to end against the live stack TestE2E set up:
// no inbound trust on the client, name-based ssh via the Host alias block,
// mutation propagation through `certhold-cli status`/`refresh`, the rekey
// pull path, and certhold-cli self-update. Invoked as TestE2E step 10 so it
// reuses the running manager (init + serve from step 01).
package e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

const (
	hostPeerName   = "app01"
	hostPeerSvc    = "peer4"
	clientPeerName = "laptop"
	clientPeerSvc  = "peer5"

	pendingNotice = "client peer " + clientPeerName +
		": changes pending until 'certhold-cli refresh' runs on it"
)

// enrollClientOneLiner runs `certhold enroll <name> --user <user> --groups
// <groups> --client` and returns the install one-liner. Client enrolls print a
// second advisory line after the one-liner, so only the first line is returned.
func enrollClientOneLiner(ctx context.Context, t *testing.T, name, user, groups string) string {
	t.Helper()
	out := certhold(ctx, t, "enroll", name, "--user", user, "--groups", groups, "--client")
	if !strings.Contains(out, "client-style peer; manager cannot push to it") {
		t.Fatalf("enroll --client %s missing client-style advisory line:\n%s", name, out)
	}
	line := strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
	if !strings.Contains(line, "curl") || !strings.Contains(line, "| bash") {
		t.Fatalf("enroll --client %s produced unexpected one-liner: %q", name, line)
	}
	return line
}

// certholdCLI runs the installed certhold-cli on a peer AS the deploy user
// (the install drops it at ~/.local/bin which is not on the container PATH,
// so it is invoked by absolute path).
func certholdCLI(ctx context.Context, t *testing.T, service, args string) execResult {
	t.Helper()
	res := composeExec(ctx, t, targetUser, service, "\"$HOME\"/.local/bin/certhold-cli "+args)
	t.Logf("certhold-cli %s on %s exit=%d:\n%s", args, service, res.exitCode, res.out)
	return res
}

// cliRefreshOK runs `certhold-cli refresh` on the peer and fails the test on a
// non-zero exit or a missing per-instance "refreshed <name>" confirmation.
func cliRefreshOK(ctx context.Context, t *testing.T, service string) string {
	t.Helper()
	res := certholdCLI(ctx, t, service, "refresh")
	if res.exitCode != 0 {
		t.Fatalf("certhold-cli refresh on %s exit=%d (want 0):\n%s", service, res.exitCode, res.out)
	}
	if !strings.Contains(res.out, "refreshed "+clientPeerName) {
		t.Fatalf("certhold-cli refresh on %s did not confirm 'refreshed %s':\n%s", service, clientPeerName, res.out)
	}
	return res.out
}

// assertCLIVerdict runs `certhold-cli status` on the peer and asserts the
// verdict line. wantVerdict is matched against the script's fixed-format
// output ("  verdict:    <verdict>").
func assertCLIVerdict(ctx context.Context, t *testing.T, service, wantVerdict string) {
	t.Helper()
	res := certholdCLI(ctx, t, service, "status")
	if res.exitCode != 0 {
		t.Fatalf("certhold-cli status on %s exit=%d (want 0):\n%s", service, res.exitCode, res.out)
	}
	if !strings.Contains(res.out, "verdict:    "+wantVerdict) {
		t.Fatalf("certhold-cli status on %s: want verdict %q:\n%s", service, wantVerdict, res.out)
	}
}

// sshAliasTry attempts a non-interactive, pubkey-only SSH from fromService
// using ONLY the bare Host alias (no user@, no address): both HostName and
// User must come from the keyed certhold block in ~/.ssh/config. The pinned
// options mirror sshTryAs.
func sshAliasTry(ctx context.Context, t *testing.T, fromService, alias string) int {
	t.Helper()
	sshCmd := fmt.Sprintf(
		"ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=publickey "+
			"-o PasswordAuthentication=no -o BatchMode=yes -o ConnectTimeout=10 "+
			"%s true", alias)
	res := composeExec(ctx, t, targetUser, fromService, sshCmd)
	t.Logf("ssh %s->%s (alias) exit=%d output=%q", fromService, alias, res.exitCode, strings.TrimSpace(res.out))
	return res.exitCode
}

// runClientPeerFlow is TestE2E step 10. Substeps 01-07 map 1:1 to the seven
// numbered steps of issue #97 (step 1's "manager init + serve" half is
// TestE2E step 01).
func runClientPeerFlow(ctx context.Context, t *testing.T, instanceKey string) {
	home := "/home/" + targetUser
	sshDir := home + "/.ssh"
	confPath := sshDir + "/certhold_" + instanceKey + ".conf"
	cliPath := home + "/.local/bin/certhold-cli"

	t.Run("01_enroll_host_and_client", func(t *testing.T) {
		// peer4 will receive real pushes (group allow/disallow, rekey), so the
		// manager's outbound known_hosts must trust its host key.
		seedManagerKnownHosts(ctx, t, hostPeerSvc)

		certhold(ctx, t, "group", "create", "app")
		line := enrollOneLiner(ctx, t, hostPeerName, hostPeerSvc, targetUser, "app")
		res := composeExec(ctx, t, targetUser, hostPeerSvc, line)
		if res.exitCode != 0 {
			t.Fatalf("install %s on %s exit=%d:\n%s", hostPeerName, hostPeerSvc, res.exitCode, res.out)
		}
		assertPeerInstall(ctx, t, hostPeerSvc, targetUser, home, instanceKey, []string{"manager", "app"})

		clientLine := enrollClientOneLiner(ctx, t, clientPeerName, targetUser, "app")
		res = composeExec(ctx, t, targetUser, clientPeerSvc, clientLine)
		if res.exitCode != 0 {
			t.Fatalf("install %s on %s exit=%d:\n%s", clientPeerName, clientPeerSvc, res.exitCode, res.out)
		}
	})

	t.Run("02_client_files", func(t *testing.T) {
		// NO certhold cert-authority line landed on the client (the bundle
		// ships no ca_authorized_keys), whether or not the file exists.
		res := composeExec(ctx, t, targetUser, clientPeerSvc,
			"if [ -f "+sshDir+"/authorized_keys ] && grep -q cert-authority "+sshDir+"/authorized_keys; then echo HAS_CA; else echo NO_CA; fi")
		if !strings.Contains(res.out, "NO_CA") {
			t.Fatalf("%s: client authorized_keys unexpectedly carries a cert-authority line:\n%s", clientPeerSvc, res.out)
		}

		for _, f := range []string{
			sshDir + "/id_ed25519_" + instanceKey,
			sshDir + "/id_ed25519_" + instanceKey + "-cert.pub",
		} {
			res := composeExec(ctx, t, targetUser, clientPeerSvc, "test -f "+f+" && echo ok")
			if !strings.Contains(res.out, "ok") {
				t.Fatalf("%s: expected identity file %s missing:\n%s", clientPeerSvc, f, res.out)
			}
		}

		res = composeExec(ctx, t, targetUser, clientPeerSvc, "test -x "+cliPath+" && echo ok")
		if !strings.Contains(res.out, "ok") {
			t.Fatalf("%s: certhold-cli not installed executable at %s:\n%s", clientPeerSvc, cliPath, res.out)
		}

		res = composeExec(ctx, t, targetUser, clientPeerSvc, "stat -c %a "+confPath)
		if strings.TrimSpace(res.out) != "600" {
			t.Fatalf("%s: conf %s mode = %q, want 600", clientPeerSvc, confPath, strings.TrimSpace(res.out))
		}
		res = composeExec(ctx, t, targetUser, clientPeerSvc, "grep -c '^PULL_TOKEN=' "+confPath)
		if strings.TrimSpace(res.out) != "1" {
			t.Fatalf("%s: conf %s missing PULL_TOKEN line:\n%s", clientPeerSvc, confPath, res.out)
		}

		cfg := composeExec(ctx, t, targetUser, clientPeerSvc, "cat "+sshDir+"/config")
		if want := "# BEGIN certhold " + instanceKey + " v2"; !strings.Contains(cfg.out, want) {
			t.Fatalf("%s: ~/.ssh/config missing keyed block %q:\n%s", clientPeerSvc, want, cfg.out)
		}
	})

	t.Run("03_client_to_host_ssh_via_alias", func(t *testing.T) {
		// The install-time block carries no Host stanzas; clients receive the
		// reachable-host aliases via the pull channel, so the first refresh
		// must deliver the app01 alias (HostName+User) into the keyed block.
		cliRefreshOK(ctx, t, clientPeerSvc)
		cfg := composeExec(ctx, t, targetUser, clientPeerSvc, "cat "+sshDir+"/config")
		for _, want := range []string{
			"# BEGIN certhold " + instanceKey + " v2",
			"Host " + hostPeerName,
			"HostName " + hostPeerSvc,
			"User " + targetUser,
		} {
			if !strings.Contains(cfg.out, want) {
				t.Fatalf("%s: ~/.ssh/config missing %q after refresh:\n%s", clientPeerSvc, want, cfg.out)
			}
		}

		// `app01` is NOT a DNS name on the compose network (the service is
		// `peer4`), so a successful bare-alias ssh proves the HostName/User
		// resolution came from the keyed config block. First pin the resolved
		// values explicitly via `ssh -G`.
		res := composeExec(ctx, t, targetUser, clientPeerSvc,
			"ssh -G "+hostPeerName+" | grep -E '^(hostname|user) '")
		if !strings.Contains(res.out, "hostname "+hostPeerSvc) || !strings.Contains(res.out, "user "+targetUser) {
			t.Fatalf("%s: ssh -G %s did not resolve HostName/User from the certhold block:\n%s",
				clientPeerSvc, hostPeerName, res.out)
		}
		if code := sshAliasTry(ctx, t, clientPeerSvc, hostPeerName); code != 0 {
			t.Fatalf("%s->%s via Host alias failed (exit %d, want 0)", clientPeerSvc, hostPeerName, code)
		}
	})

	t.Run("04_no_inbound_to_client", func(t *testing.T) {
		if code := sshTry(ctx, t, hostPeerSvc, clientPeerSvc); code == 0 {
			t.Fatalf("%s->%s unexpectedly succeeded (want non-zero: client peers carry no inbound trust)",
				hostPeerSvc, clientPeerSvc)
		}
	})

	t.Run("05_mutation_pending_refresh", func(t *testing.T) {
		// Step 03's refresh baselined the client at the current fleet rev
		// (the enroll-time conf ships LAST_REV=0, which would read as stale
		// on its own), so the later "stale" verdict is attributable to the
		// mutations below.
		assertCLIVerdict(ctx, t, clientPeerSvc, "up-to-date")
		if code := sshAliasTry(ctx, t, clientPeerSvc, hostPeerName); code != 0 {
			t.Fatalf("%s->%s failed (exit %d) after baseline refresh (want 0)", clientPeerSvc, hostPeerName, code)
		}

		// Move laptop from group app to a new group lap, and flip app01's
		// inbound allow-list from {app} to {lap}. The host side is pushed
		// immediately; the client side only lands on its next pull.
		certhold(ctx, t, "group", "create", "lap")
		out := certhold(ctx, t, "update", clientPeerName, "--groups", "lap")
		if !strings.Contains(out, pendingNotice) {
			t.Fatalf("update %s missing pending-refresh notice %q:\n%s", clientPeerName, pendingNotice, out)
		}
		if !strings.Contains(out, "updated "+clientPeerName) {
			t.Fatalf("update %s did not confirm success:\n%s", clientPeerName, out)
		}
		certhold(ctx, t, "group", "allow", "lap", "--on", hostPeerName)
		certhold(ctx, t, "group", "disallow", "app", "--on", hostPeerName)

		// Pre-refresh the client still presents the old cert (principals
		// laptop,app) while app01 now allows only {manager,lap}: access closed.
		if code := sshAliasTry(ctx, t, clientPeerSvc, hostPeerName); code == 0 {
			t.Fatalf("%s->%s unexpectedly succeeded before refresh (old cert lacks the lap principal)",
				clientPeerSvc, hostPeerName)
		}
		assertCLIVerdict(ctx, t, clientPeerSvc, "stale")

		// refresh pulls the re-signed cert (principals laptop,lap): access opens.
		cliRefreshOK(ctx, t, clientPeerSvc)
		assertCLIVerdict(ctx, t, clientPeerSvc, "up-to-date")
		if code := sshAliasTry(ctx, t, clientPeerSvc, hostPeerName); code != 0 {
			t.Fatalf("%s->%s failed (exit %d) after refresh (want 0: new cert carries lap)",
				clientPeerSvc, hostPeerName, code)
		}
	})

	t.Run("06_rekey_pull_path", func(t *testing.T) {
		out := certhold(ctx, t, "rekey")
		if !strings.Contains(out, pendingNotice) {
			t.Fatalf("rekey missing pending-refresh notice %q:\n%s", pendingNotice, out)
		}
		if !strings.Contains(out, "rekeyed "+clientPeerName) {
			t.Fatalf("rekey did not re-sign %s for pull:\n%s", clientPeerName, out)
		}

		// app01 rotated to the new CA via push; the client's local cert is
		// still signed by the retired CA and must be rejected.
		if code := sshAliasTry(ctx, t, clientPeerSvc, hostPeerName); code == 0 {
			t.Fatalf("%s->%s unexpectedly succeeded after rekey (old-CA cert must be rejected)",
				clientPeerSvc, hostPeerName)
		}
		assertCLIVerdict(ctx, t, clientPeerSvc, "stale")

		cliRefreshOK(ctx, t, clientPeerSvc)
		assertCLIVerdict(ctx, t, clientPeerSvc, "up-to-date")
		if code := sshAliasTry(ctx, t, clientPeerSvc, hostPeerName); code != 0 {
			t.Fatalf("%s->%s failed (exit %d) after refresh (want 0: new-CA cert restored)",
				clientPeerSvc, hostPeerName, code)
		}
	})

	t.Run("07_cli_self_update", func(t *testing.T) {
		marker := "# e2e-doctored-marker"
		res := composeExec(ctx, t, targetUser, clientPeerSvc,
			"printf '%s\\n' '"+marker+"' >> "+cliPath+" && echo ok")
		if !strings.Contains(res.out, "ok") {
			t.Fatalf("%s: failed to doctor %s:\n%s", clientPeerSvc, cliPath, res.out)
		}
		res = composeExec(ctx, t, targetUser, clientPeerSvc, "grep -q '"+marker+"' "+cliPath+" && echo doctored")
		if !strings.Contains(res.out, "doctored") {
			t.Fatalf("%s: marker did not land in %s:\n%s", clientPeerSvc, cliPath, res.out)
		}

		out := cliRefreshOK(ctx, t, clientPeerSvc)
		if !strings.Contains(out, "self-updated from bundle at") {
			t.Fatalf("refresh with doctored cli did not report self-update:\n%s", out)
		}

		res = composeExec(ctx, t, targetUser, clientPeerSvc,
			"if grep -q '"+marker+"' "+cliPath+"; then echo STILL_DOCTORED; else echo PRISTINE; fi")
		if !strings.Contains(res.out, "PRISTINE") {
			t.Fatalf("%s: %s still carries the doctored marker after self-update:\n%s",
				clientPeerSvc, cliPath, res.out)
		}
	})
}
