//go:build e2e

// Re-enroll e2e flow (issue #192): `certhold enroll <existing>` is an
// idempotent in-place reconfigure with stage-at-mint / commit-at-redemption
// semantics. Invoked as TestE2E step 12 against the state steps 01-11 built:
// web01@peer1 (inbound, group web), app01@peer4 (inbound, allows lap),
// laptop@peer5 (client, group lap).
package e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

const reenrollAdvisory = "re-enroll minted for existing peer"

// reenrollOneLiner runs `certhold enroll <name> [extra...]` for an EXISTING
// peer, asserts the distinct re-enroll advisory is printed, and returns the
// install one-liner (the first output line).
func reenrollOneLiner(ctx context.Context, t *testing.T, name string, extra ...string) string {
	t.Helper()
	out := certhold(ctx, t, append([]string{"enroll", name}, extra...)...)
	if !strings.Contains(out, reenrollAdvisory+" "+name) {
		t.Fatalf("re-enroll %s missing advisory %q:\n%s", name, reenrollAdvisory, out)
	}
	line := strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
	if !strings.Contains(line, "curl") || !strings.Contains(line, "| bash") {
		t.Fatalf("re-enroll %s produced unexpected one-liner: %q", name, line)
	}
	return line
}

// cliRefreshPeerOK runs `certhold-cli refresh` on the peer asserting a
// per-instance "refreshed <peerName>" confirmation (generic variant of
// cliRefreshOK, which is pinned to the laptop peer).
func cliRefreshPeerOK(ctx context.Context, t *testing.T, service, peerName string) string {
	t.Helper()
	res := certholdCLI(ctx, t, service, "refresh")
	if res.exitCode != 0 {
		t.Fatalf("certhold-cli refresh on %s exit=%d (want 0):\n%s", service, res.exitCode, res.out)
	}
	if !strings.Contains(res.out, "refreshed "+peerName) {
		t.Fatalf("certhold-cli refresh on %s did not confirm 'refreshed %s':\n%s", service, peerName, res.out)
	}
	return res.out
}

// pullTokenOf reads the standing PULL_TOKEN from the peer's keyed conf file.
func pullTokenOf(ctx context.Context, t *testing.T, service, instanceKey string) string {
	t.Helper()
	conf := "/home/" + targetUser + "/.ssh/certhold_" + instanceKey + ".conf"
	res := composeExec(ctx, t, targetUser, service, "sed -n 's/^PULL_TOKEN=//p' "+conf)
	tok := strings.TrimSpace(res.out)
	if res.exitCode != 0 || tok == "" {
		t.Fatalf("could not read PULL_TOKEN from %s on %s (exit=%d):\n%s", conf, service, res.exitCode, res.out)
	}
	return tok
}

// runReenrollFlow is TestE2E step 12.
func runReenrollFlow(ctx context.Context, t *testing.T, instanceKey string) {
	home := "/home/" + targetUser
	sshDir := home + "/.ssh"

	t.Run("01_mint_leaves_live_peer_untouched", func(t *testing.T) {
		// Mint a re-enroll for web01 with NO flags: defaults come from the DB.
		// Everything below must keep working against web01's OLD key while the
		// one-liner sits unredeemed.
		reenrollOneLiner(ctx, t, "web01")

		// The live peer still authenticates with its old cert.
		if code := sshTry(ctx, t, "peer1", "peer1"); code != 0 {
			t.Fatalf("peer1->peer1 failed (exit %d) after an unredeemed re-enroll mint (want 0: live peer untouched)", code)
		}
		// A group-edit push cycle still works: update re-signs the OLD key
		// (the DB row was not touched by the mint) and pushes it to peer1.
		out := certhold(ctx, t, "update", "web01", "--groups", "web")
		if !strings.Contains(out, "updated web01") {
			t.Fatalf("update web01 with an outstanding re-enroll mint did not confirm success:\n%s", out)
		}
		if code := sshTry(ctx, t, "peer1", "peer1"); code != 0 {
			t.Fatalf("peer1->peer1 failed (exit %d) after push against the old key (want 0)", code)
		}
	})

	t.Run("02_supersede_and_redeem", func(t *testing.T) {
		// The step-01 mint was superseded by minting again; only the newest
		// one-liner may redeem. (Redeeming the new one below also proves the
		// supersede did not invalidate the peer.)
		firstLine := reenrollOneLiner(ctx, t, "web01")
		secondLine := reenrollOneLiner(ctx, t, "web01")

		// The superseded token must answer 404. (Running its one-liner would
		// "succeed" with exit 0 — `curl -f | bash` takes bash's exit — so the
		// HTTP status is the honest check.)
		firstURL := strings.Fields(firstLine)[2]
		status := composeExec(ctx, t, "", "manager",
			fmt.Sprintf("curl -ks -o /dev/null -w '%%{http_code}' %s", firstURL))
		if strings.TrimSpace(status.out) != "404" {
			t.Fatalf("superseded enroll script answered %q, want 404", strings.TrimSpace(status.out))
		}

		// The current one redeems and reconfigures web01 in place.
		res := composeExec(ctx, t, targetUser, "peer1", secondLine)
		if res.exitCode != 0 {
			t.Fatalf("re-enroll install on peer1 exit=%d:\n%s", res.exitCode, res.out)
		}
		assertPeerInstall(ctx, t, "peer1", targetUser, home, instanceKey, []string{"manager", "web"})

		// The re-enrolled peer is fully functional: fresh cert authenticates,
		// and the manager can still push to it (trust line preserved).
		if code := sshTry(ctx, t, "peer1", "peer1"); code != 0 {
			t.Fatalf("peer1->peer1 failed (exit %d) after re-enroll redemption (want 0: new key+cert live)", code)
		}
		out := certhold(ctx, t, "update", "web01", "--groups", "web")
		if !strings.Contains(out, "updated web01") {
			t.Fatalf("update web01 after re-enroll did not confirm success:\n%s", out)
		}
	})

	t.Run("03_reenroll_ships_certhold_cli", func(t *testing.T) {
		// The motivating case: web01 was enrolled before this step ever ran
		// refresh; the re-enroll installed certhold-cli + a working pull
		// channel (new pull token in the replaced conf).
		cliPath := home + "/.local/bin/certhold-cli"
		res := composeExec(ctx, t, targetUser, "peer1", "test -x "+cliPath+" && echo ok")
		if !strings.Contains(res.out, "ok") {
			t.Fatalf("certhold-cli not installed on peer1 by the re-enroll:\n%s", res.out)
		}
		cliRefreshPeerOK(ctx, t, "peer1", "web01")
	})

	t.Run("04_client_reenroll_rotates_pull_token", func(t *testing.T) {
		// Re-enroll the client peer with no flags: it stays client (the DB
		// default) and gets a fresh pull token; the old one stops answering.
		oldTok := pullTokenOf(ctx, t, clientPeerSvc, instanceKey)

		out := certhold(ctx, t, "enroll", clientPeerName)
		if !strings.Contains(out, reenrollAdvisory+" "+clientPeerName) {
			t.Fatalf("client re-enroll missing advisory:\n%s", out)
		}
		if !strings.Contains(out, "client-style peer; manager cannot push to it") {
			t.Fatalf("client re-enroll must keep the client advisory (client-ness defaults from the DB):\n%s", out)
		}
		line := strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
		res := composeExec(ctx, t, targetUser, clientPeerSvc, line)
		if res.exitCode != 0 {
			t.Fatalf("client re-enroll install on %s exit=%d:\n%s", clientPeerSvc, res.exitCode, res.out)
		}

		newTok := pullTokenOf(ctx, t, clientPeerSvc, instanceKey)
		if newTok == oldTok {
			t.Fatalf("pull token did not rotate on re-enroll")
		}
		status := composeExec(ctx, t, "", "manager",
			fmt.Sprintf("curl -ks -o /dev/null -w '%%{http_code}' https://manager:8443/pull/%s", oldTok))
		if strings.TrimSpace(status.out) != "404" {
			t.Fatalf("old pull token answered %q, want 404 after rotation", strings.TrimSpace(status.out))
		}
		// The refreshed pull channel works end to end with the new token.
		cliRefreshPeerOK(ctx, t, clientPeerSvc, clientPeerName)
		assertCLIVerdict(ctx, t, clientPeerSvc, "up-to-date")
	})

	t.Run("05_client_to_inbound", func(t *testing.T) {
		// Re-enroll laptop as inbound: the bundle now carries a trust line and
		// the commit flips inbound + seeds allowed=groups, making it pushable.
		line := reenrollOneLiner(ctx, t, clientPeerName, "--client=false", "--address", clientPeerSvc)
		res := composeExec(ctx, t, targetUser, clientPeerSvc, line)
		if res.exitCode != 0 {
			t.Fatalf("inbound re-enroll install on %s exit=%d:\n%s", clientPeerSvc, res.exitCode, res.out)
		}
		assertPeerInstall(ctx, t, clientPeerSvc, targetUser, home, instanceKey, []string{"manager", "lap"})

		// The redemption probe must auto-capture peer5's host key, after which
		// a push must actually dial it (no pending-refresh notice).
		assertManagerKnownHostsHas(ctx, t, clientPeerSvc)
		out := certhold(ctx, t, "update", clientPeerName, "--groups", "lap")
		if !strings.Contains(out, "updated "+clientPeerName) {
			t.Fatalf("update %s after inbound re-enroll did not confirm success:\n%s", clientPeerName, out)
		}
		if strings.Contains(out, "changes pending until") {
			t.Fatalf("update %s still routed to the pull channel after inbound re-enroll:\n%s", clientPeerName, out)
		}
	})

	t.Run("06_inbound_to_client_strips_trust_line", func(t *testing.T) {
		// laptop (inbound again, cert groups lap) can reach app01, which
		// allows {manager, lap}: the edge is open before the transition.
		if code := sshAliasTry(ctx, t, clientPeerSvc, hostPeerName); code != 0 {
			t.Fatalf("%s->%s failed (exit %d) before app01's client transition (want 0)", clientPeerSvc, hostPeerName, code)
		}

		line := reenrollOneLiner(ctx, t, hostPeerName, "--client")
		res := composeExec(ctx, t, targetUser, hostPeerSvc, line)
		if res.exitCode != 0 {
			t.Fatalf("client re-enroll install on %s exit=%d:\n%s", hostPeerSvc, res.exitCode, res.out)
		}
		if !strings.Contains(res.out, "removed cert-authority line") {
			t.Fatalf("client re-enroll install did not report removing the trust line:\n%s", res.out)
		}

		// The stale trust line is gone from the live peer...
		ak := composeExec(ctx, t, targetUser, hostPeerSvc,
			"if [ -f "+sshDir+"/authorized_keys ] && grep -q cert-authority "+sshDir+"/authorized_keys; then echo HAS_CA; else echo NO_CA; fi")
		if !strings.Contains(ak.out, "NO_CA") {
			t.Fatalf("%s: authorized_keys still carries a cert-authority line after client re-enroll:\n%s", hostPeerSvc, ak.out)
		}
		// ...so fleet inbound SSH is refused...
		if code := sshAliasTry(ctx, t, clientPeerSvc, hostPeerName); code == 0 {
			t.Fatalf("%s->%s unexpectedly succeeded after app01 became a client (want non-zero)", clientPeerSvc, hostPeerName)
		}
		// ...and pushes route app01 onto the pull channel instead of dialing.
		out := certhold(ctx, t, "update", hostPeerName, "--groups", "app")
		if !strings.Contains(out, "client peer "+hostPeerName+": changes pending until") {
			t.Fatalf("update %s should print the client pending notice after the transition:\n%s", hostPeerName, out)
		}
		// Its own outbound identity still works: allow app on web01 and ssh
		// app01(peer4) -> web01(peer1). (No Host alias for web01 exists in
		// app01's config — web01 did not allow app at mint — so dial peer1
		// directly; the keyed Host * block still presents app01's new cert.)
		certhold(ctx, t, "group", "allow", "app", "--on", "web01")
		if code := sshTry(ctx, t, hostPeerSvc, "peer1"); code != 0 {
			t.Fatalf("%s->peer1 failed (exit %d) after client re-enroll (want 0: outbound identity re-minted)", hostPeerSvc, code)
		}
	})
}
