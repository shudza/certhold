//go:build e2e

// Package e2e is a real end-to-end test suite for certhold. It orchestrates a
// docker compose stack (one manager + two alpine peers running real OpenSSH
// sshd) entirely through os/exec — there are NO new go.mod dependencies (no
// testcontainers, no docker SDK). It exercises certhold's actual SSH trust
// behavior end to end: enroll, update, group allow/disallow, revoke and rekey,
// asserting on real `ssh` connection exit codes (success/failure), including
// peer->peer inbound trust that unit tests cannot reach because they stub the
// pusher.
//
// The suite is gated behind the `e2e` build tag so the default `go build ./...`
// / `go test ./...` / `make test` never compile or run it. Run it with:
//
//	make e2e          # -> go test -tags e2e -count=1 -timeout 20m ./test/e2e/...
//
// It requires a working Docker daemon + `docker compose`; it cannot run in the
// sandbox the implementer/reviewer use (no docker, no root).
package e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	// targetUser is the Unix user the v2 user-mode install targets on each peer.
	targetUser = "deploy"
	// composeProject isolates this stack's containers/network/volumes so
	// `down -v` only tears down what this suite created.
	composeProject = "certhold-e2e"
)

// composeArgs returns the base `docker compose` argv with our file + project
// name. Run from the test/e2e directory so the relative build contexts resolve.
func composeArgs(extra ...string) []string {
	base := []string{"compose", "-p", composeProject, "-f", "docker-compose.yml"}
	return append(base, extra...)
}

// runCompose runs `docker compose <args...>` and returns combined output. A
// non-zero exit is returned as an error (callers that tolerate failure, e.g.
// teardown, ignore it).
func runCompose(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", composeArgs(args...)...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

// execResult captures the outcome of a command run inside a container.
type execResult struct {
	out      string
	exitCode int
}

// composeExec runs `docker compose exec -T [-u user] <service> sh -c <script>`
// and returns its combined output and exit code. -T disables pseudo-tty
// allocation (required for non-interactive automation). When user is non-empty
// the command runs as that user (the v2 install one-liner must run AS the
// target user because it reads $HOME and `id -un`).
func composeExec(ctx context.Context, t *testing.T, user, service, script string) execResult {
	t.Helper()
	args := []string{"exec", "-T"}
	if user != "" {
		args = append(args, "-u", user)
	}
	args = append(args, service, "sh", "-c", script)
	cmd := exec.CommandContext(ctx, "docker", composeArgs(args...)...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	res := execResult{out: out.String()}
	if err == nil {
		res.exitCode = 0
		return res
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		res.exitCode = ee.ExitCode()
		return res
	}
	// A non-exit error (e.g. docker itself failed to start the exec) is fatal:
	// the stack is unusable and continuing would produce misleading results.
	t.Fatalf("docker compose exec %s %q failed to run: %v\noutput:\n%s", service, script, err, out.String())
	return res
}

// certhold runs `certhold <args>` on the manager and fails the test if it does
// not exit 0. data-dir/db default to /root/.certhold under the root account the
// manager container runs as.
func certhold(ctx context.Context, t *testing.T, args ...string) string {
	t.Helper()
	script := "certhold " + strings.Join(args, " ")
	res := composeExec(ctx, t, "", "manager", script)
	if res.exitCode != 0 {
		t.Fatalf("certhold %v exit=%d\noutput:\n%s", args, res.exitCode, res.out)
	}
	return res.out
}

// certholdExpectFail runs `certhold <args>` on the manager and asserts a
// NON-zero exit (e.g. updating a revoked peer must error).
func certholdExpectFail(ctx context.Context, t *testing.T, args ...string) string {
	t.Helper()
	script := "certhold " + strings.Join(args, " ")
	res := composeExec(ctx, t, "", "manager", script)
	if res.exitCode == 0 {
		t.Fatalf("certhold %v unexpectedly succeeded\noutput:\n%s", args, res.out)
	}
	return res.out
}

// sshTry attempts a non-interactive, pubkey-only SSH from `fromService` to
// deploy@<toHost> running `true`, and returns the exit code. The options pin
// the attempt to certificate/pubkey auth so the result reflects ONLY certhold's
// trust state, not host-key prompts or password fallback:
//
//	StrictHostKeyChecking=no     - peers bootstrap host trust via TOFU; don't
//	                               block on an unknown host key (we are testing
//	                               cert *user* auth, not host identity).
//	PreferredAuthentications,
//	PasswordAuthentication=no    - never fall back to a password; a non-zero
//	                               exit then means "cert not accepted".
//	BatchMode=yes                - never prompt; fail fast instead.
//
// The client presents web01's/db01's cert via the ~/.ssh/config block the v2
// install spliced in (CertificateFile/IdentityFile), so no -i is needed.
func sshTry(ctx context.Context, t *testing.T, fromService, toHost string) int {
	t.Helper()
	sshCmd := fmt.Sprintf(
		"ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=publickey "+
			"-o PasswordAuthentication=no -o BatchMode=yes -o ConnectTimeout=10 "+
			"%s@%s true", targetUser, toHost)
	res := composeExec(ctx, t, targetUser, fromService, sshCmd)
	t.Logf("ssh %s->%s exit=%d output=%q", fromService, toHost, res.exitCode, strings.TrimSpace(res.out))
	return res.exitCode
}

// waitForManagerHTTPS blocks until the manager's serve endpoint answers TLS on
// :8443 or the deadline passes. It probes from inside the manager container so
// no host port mapping is required.
func waitForManagerHTTPS(ctx context.Context, t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		// curl -k tolerates the self-signed cert. A zero exit means curl got an
		// HTTP response (any status, even 404 on this bogus path), proving the
		// TLS listener is bound. No -f (404 must still count) and no `|| true`
		// (it would mask the exit code we rely on); stderr is merged into out by
		// composeExec but ignored here since we gate on the exit code, not output.
		res := composeExec(ctx, t, "", "manager",
			"curl -ks -o /dev/null https://manager:8443/enroll/__probe__")
		if res.exitCode == 0 {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("manager HTTPS :8443 did not become ready within deadline")
}

// waitForSSHD blocks until each peer's sshd answers on :22. We probe with the
// peer's own ssh-keyscan against localhost (the install image has
// openssh-client); a non-empty key line means sshd completed the handshake.
// (We deliberately avoid bash-only /dev/tcp since composeExec runs `sh`.)
func waitForSSHD(ctx context.Context, t *testing.T, services ...string) {
	t.Helper()
	for _, svc := range services {
		deadline := time.Now().Add(60 * time.Second)
		ready := false
		for time.Now().Before(deadline) {
			res := composeExec(ctx, t, "", svc,
				"ssh-keyscan -T 5 -p 22 127.0.0.1 2>/dev/null | grep -q . && echo up || echo down")
			if strings.Contains(res.out, "up") {
				ready = true
				break
			}
			time.Sleep(time.Second)
		}
		if !ready {
			t.Fatalf("sshd on %s did not become ready within deadline", svc)
		}
	}
}

// enrollOneLiner runs `certhold enroll` and returns the printed install
// one-liner (`curl -kfsSL .../enroll/<tok>.sh | bash`).
func enrollOneLiner(ctx context.Context, t *testing.T, name, address, groups string) string {
	t.Helper()
	out := certhold(ctx, t, "enroll", name,
		"--address", address, "--mode", "user", "--user", targetUser,
		"--groups", groups)
	line := strings.TrimSpace(out)
	if !strings.Contains(line, "curl") || !strings.Contains(line, "| bash") {
		t.Fatalf("enroll %s produced unexpected one-liner: %q", name, line)
	}
	return line
}

// seedManagerKnownHosts populates the manager's OUTBOUND known_hosts with the
// peers' host keys. This is REQUIRED: certhold's push (update/group/revoke/
// rekey) verifies the peer host key strictly via knownhosts.New on
// self/home/deploy/.ssh/known_hosts, which is EMPTY after a fresh v2 user-mode
// init (user mode ships no CA-signed host certs, so there is no @cert-authority
// seed line either). Without seeding, every manager->peer push fails host-key
// verification. We ssh-keyscan each peer under the exact name the manager dials
// it by (the enroll --address value, surfaced by Peer.DialHost()).
func seedManagerKnownHosts(ctx context.Context, t *testing.T, dialHosts ...string) {
	t.Helper()
	khPath := "/root/.certhold/self/home/" + targetUser + "/.ssh/known_hosts"
	for _, h := range dialHosts {
		res := composeExec(ctx, t, "", "manager",
			fmt.Sprintf("ssh-keyscan -T 10 %s >> %s 2>/dev/null", h, khPath))
		if res.exitCode != 0 {
			t.Fatalf("ssh-keyscan %s failed exit=%d:\n%s", h, res.exitCode, res.out)
		}
	}
	// Sanity: the file must now be non-empty or pushes will still fail.
	res := composeExec(ctx, t, "", "manager", "wc -c < "+khPath)
	if strings.TrimSpace(res.out) == "0" || strings.TrimSpace(res.out) == "" {
		t.Fatalf("manager known_hosts %s is empty after seeding:\n%s", khPath, res.out)
	}
}

// TestMain brings the compose stack up (building images) before the suite and
// always tears it down with `down -v` afterwards, even on panic/failure.
func TestMain(m *testing.M) {
	if _, err := exec.LookPath("docker"); err != nil {
		fmt.Fprintln(os.Stderr, "e2e: docker not found in PATH; this suite requires Docker + docker compose")
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// Best-effort pre-clean in case a previous run left containers around.
	_, _ = runCompose(ctx, "down", "-v", "--remove-orphans")

	upOut, err := runCompose(ctx, "up", "--build", "-d")
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: compose up failed: %v\n%s\n", err, upOut)
		// Tear down whatever came up before bailing.
		_, _ = runCompose(context.Background(), "down", "-v", "--remove-orphans")
		os.Exit(1)
	}

	code := m.Run()

	// Robust teardown regardless of test outcome. Use a fresh context so a
	// timed-out suite still cleans up.
	downCtx, downCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer downCancel()
	if out, derr := runCompose(downCtx, "down", "-v", "--remove-orphans"); derr != nil {
		fmt.Fprintf(os.Stderr, "e2e: compose down failed: %v\n%s\n", derr, out)
	}

	os.Exit(code)
}

// TestE2E is one ordered test: each t.Run step builds on the state the previous
// steps established (a real deployment lifecycle), so the subtests are NOT
// independent and must run in order. A failure in an early step aborts the rest
// via t.Fatalf to avoid cascading misleading failures.
func TestE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	// instanceKey is discovered after init and used to assert the namespaced
	// identity files the v2 install writes.
	var instanceKey string

	t.Run("01_init_and_serve", func(t *testing.T) {
		// init writes the CA + manager self files and persists base_url. Mode
		// user/user deploy means the manager's own identity lives under
		// self/home/deploy/.ssh/ with v2-namespaced filenames. Passphrases are
		// supplied via CERTHOLD_CA_PASSPHRASE / CERTHOLD_PEER_PASSPHRASE on the
		// manager service, so --no-prompt does not block on a tty.
		certhold(ctx, t, "init", "--mode", "user", "--user", targetUser,
			"--listen-ip", "0.0.0.0", "--no-prompt")

		// Start serve in the background inside the manager container. It listens
		// HTTPS (self-signed) on :8443; the install one-liner uses curl -k.
		res := composeExec(ctx, t, "", "manager",
			"setsid sh -c 'certhold serve --addr :8443 >/tmp/serve.log 2>&1 &' ; sleep 1; cat /tmp/serve.log || true")
		t.Logf("serve launch output:\n%s", res.out)

		waitForManagerHTTPS(ctx, t)
		waitForSSHD(ctx, t, "peer1", "peer2")

		// Capture the instance key from the manager's namespaced self key file.
		ls := composeExec(ctx, t, "", "manager",
			"ls /root/.certhold/self/home/"+targetUser+"/.ssh/")
		t.Logf("manager self .ssh contents:\n%s", ls.out)
		instanceKey = parseInstanceKey(t, ls.out)
		if instanceKey == "" {
			t.Fatalf("could not determine instance key from self .ssh listing:\n%s", ls.out)
		}
		t.Logf("instance key = %s", instanceKey)
	})

	t.Run("02_enroll_web01_install_peer1", func(t *testing.T) {
		line := enrollOneLiner(ctx, t, "web01", "peer1", "web")
		// Run the install one-liner AS deploy on peer1.
		res := composeExec(ctx, t, targetUser, "peer1", line)
		if res.exitCode != 0 {
			t.Fatalf("install on peer1 exit=%d:\n%s", res.exitCode, res.out)
		}
		assertPeerInstall(ctx, t, "peer1", instanceKey, []string{"manager", "web"})
	})

	t.Run("03_enroll_db01_install_peer2", func(t *testing.T) {
		line := enrollOneLiner(ctx, t, "db01", "peer2", "db")
		res := composeExec(ctx, t, targetUser, "peer2", line)
		if res.exitCode != 0 {
			t.Fatalf("install on peer2 exit=%d:\n%s", res.exitCode, res.out)
		}
		assertPeerInstall(ctx, t, "peer2", instanceKey, []string{"manager", "db"})

		// Now that both peers' sshd are reachable, seed the manager's outbound
		// known_hosts so subsequent pushes pass strict host-key verification.
		seedManagerKnownHosts(ctx, t, "peer1", "peer2")
	})

	t.Run("04_manager_push_update_web01", func(t *testing.T) {
		// Proves manager cert-auth INTO peer1: update dials peer1 with the
		// manager cert, writes the reissued cert, and runs VerifyHealth (`true`).
		//
		// MAINTAINER NOTE (suspected product bug): unlike `group`/`revoke`/`rekey`
		// — which set pushOpts.User = pushUser(peer)/pushUser(self) — `update` in
		// internal/cli/update.go does NOT set pushOpts.User, so sshpush.Dial
		// defaults the login user to "root". A v2 user-mode peer only trusts the
		// manager CA in ~deploy/.ssh, not root's, so this dial is expected to FAIL
		// as root@peer1 until update sets the target user. If this step fails with
		// an ssh/auth error, that is the bug, not the harness. See the PR body.
		out := certhold(ctx, t, "update", "web01", "--groups", "web")
		if !strings.Contains(out, "updated web01") {
			t.Fatalf("update web01 did not confirm success:\n%s", out)
		}
	})

	t.Run("05_group_allow_disallow_peer_mesh", func(t *testing.T) {
		// web01 currently carries principals {web01, web}. db01 allows
		// {manager, db}. So peer1(web01)->peer2(db01) must be REJECTED.
		if code := sshTry(ctx, t, "peer1", "peer2"); code == 0 {
			t.Fatalf("peer1->peer2 unexpectedly succeeded before allowing web on db01 (want non-zero)")
		}

		// Allow `web` as an inbound principal on db01 (manager rewrites
		// peer2's ~deploy/.ssh/authorized_keys principals=...).
		certhold(ctx, t, "group", "allow", "web", "--on", "db01")
		if code := sshTry(ctx, t, "peer1", "peer2"); code != 0 {
			t.Fatalf("peer1->peer2 failed (exit %d) after allowing web on db01 (want 0)", code)
		}

		// Disallow it again; the mesh edge must close.
		certhold(ctx, t, "group", "disallow", "web", "--on", "db01")
		if code := sshTry(ctx, t, "peer1", "peer2"); code == 0 {
			t.Fatalf("peer1->peer2 unexpectedly succeeded after disallowing web on db01 (want non-zero)")
		}
	})

	t.Run("06_update_outbound_principals", func(t *testing.T) {
		// Give web01's cert the `db` principal too. db01 still allows
		// {manager, db} (web was disallowed in step 5), so web01 now satisfies
		// db01 via the `db` principal and the edge opens.
		certhold(ctx, t, "update", "web01", "--groups", "web,db")
		if code := sshTry(ctx, t, "peer1", "peer2"); code != 0 {
			t.Fatalf("peer1->peer2 failed (exit %d) after granting web01 the db principal (want 0)", code)
		}
	})

	t.Run("07_revoke_db01_partial_rekey", func(t *testing.T) {
		// Stash web01's CURRENT (old-CA) cert so step 08 can prove old certs die.
		stashOldCert(ctx, t, "peer1", instanceKey)

		// revoke db01: user-mode/v2 revoke does a partial CA rekey — web01 and
		// the manager rotate to a NEW CA; db01 is excluded and keeps trusting
		// the OLD CA. So peer1(web01, new-CA cert)->peer2(db01, old-CA trust)
		// must be rejected (db01 no longer trusts the manager's CA).
		out := certhold(ctx, t, "revoke", "db01")
		t.Logf("revoke db01 output:\n%s", out)

		if code := sshTry(ctx, t, "peer1", "peer2"); code == 0 {
			t.Fatalf("peer1->peer2 unexpectedly succeeded after revoking db01 (want non-zero: db01 trusts only the retired CA)")
		}

		// Updating a revoked peer must error.
		certholdExpectFail(ctx, t, "update", "db01", "--groups", "db")
	})

	t.Run("08_rekey_full", func(t *testing.T) {
		// Full rekey: all reachable non-revoked peers (web01 + manager) rotate to
		// a fresh CA. db01 is revoked so it is skipped. update web01 must still
		// succeed (new CA propagated and the manager can still reach peer1).
		out := certhold(ctx, t, "rekey")
		t.Logf("rekey output:\n%s", out)

		certhold(ctx, t, "update", "web01", "--groups", "web")

		// Bonus: prove old certs are invalidated by the CA rotation. We test
		// against peer1 (loopback): peer1's authorized_keys was rewritten to the
		// NEW CA by rekey, so it trusts only the new CA. (We cannot use peer2 as
		// the target: db01 is revoked and still trusts the OLD CA, so the old
		// cert would actually be accepted there.)
		//
		// First, the CURRENT (new-CA) cert into peer1 must succeed: web01's cert
		// carries principal `web` and peer1 allows {manager, web}.
		if code := sshTry(ctx, t, "peer1", "peer1"); code != 0 {
			t.Fatalf("peer1->peer1 with the current cert failed (exit %d) after rekey (want 0)", code)
		}
		// Now the stashed pre-rekey cert (signed by the retired CA) must fail.
		if code := sshOldCert(ctx, t, "peer1", "peer1", instanceKey); code == 0 {
			t.Fatalf("peer1->peer1 with the stashed pre-rekey cert unexpectedly succeeded (want non-zero)")
		}
	})
}

// parseInstanceKey extracts the 16-hex instance key from a self/.ssh listing
// that contains files like `id_ed25519_<key>` and `id_ed25519_<key>-cert.pub`.
func parseInstanceKey(t *testing.T, lsOut string) string {
	t.Helper()
	for _, f := range strings.Fields(lsOut) {
		const prefix = "id_ed25519_"
		if strings.HasPrefix(f, prefix) && strings.HasSuffix(f, "-cert.pub") {
			return strings.TrimSuffix(strings.TrimPrefix(f, prefix), "-cert.pub")
		}
	}
	return ""
}

// assertPeerInstall verifies the v2 user-mode install landed the expected files
// and trust lines in ~deploy/.ssh on the given peer.
func assertPeerInstall(ctx context.Context, t *testing.T, service, instanceKey string, wantPrincipals []string) {
	t.Helper()
	base := "/home/" + targetUser + "/.ssh"

	// Namespaced identity files exist.
	for _, f := range []string{
		"id_ed25519_" + instanceKey,
		"id_ed25519_" + instanceKey + "-cert.pub",
	} {
		res := composeExec(ctx, t, targetUser, service, "test -f "+base+"/"+f+" && echo ok")
		if !strings.Contains(res.out, "ok") {
			t.Fatalf("%s: expected identity file %s missing:\n%s", service, f, res.out)
		}
	}

	// authorized_keys carries the cert-authority line with the expected
	// principals (manager is always first).
	ak := composeExec(ctx, t, targetUser, service, "cat "+base+"/authorized_keys")
	if !strings.Contains(ak.out, "cert-authority") {
		t.Fatalf("%s: authorized_keys missing cert-authority line:\n%s", service, ak.out)
	}
	for _, p := range wantPrincipals {
		if !strings.Contains(ak.out, p) {
			t.Fatalf("%s: authorized_keys missing principal %q:\n%s", service, p, ak.out)
		}
	}

	// The keyed v2 client-config block was spliced into ~/.ssh/config.
	cfg := composeExec(ctx, t, targetUser, service, "cat "+base+"/config")
	wantBegin := "# BEGIN certhold " + instanceKey + " v2"
	if !strings.Contains(cfg.out, wantBegin) {
		t.Fatalf("%s: ~/.ssh/config missing v2 block %q:\n%s", service, wantBegin, cfg.out)
	}
}

// stashOldCert copies web01's current namespaced cert aside on peer1 so a later
// step can attempt an SSH that presents the now-stale cert.
func stashOldCert(ctx context.Context, t *testing.T, service, instanceKey string) {
	t.Helper()
	base := "/home/" + targetUser + "/.ssh"
	cert := base + "/id_ed25519_" + instanceKey + "-cert.pub"
	res := composeExec(ctx, t, targetUser, service, "cp "+cert+" "+base+"/old-cert.pub && echo ok")
	if !strings.Contains(res.out, "ok") {
		t.Fatalf("%s: failed to stash old cert:\n%s", service, res.out)
	}
}

// sshOldCert attempts an SSH from `fromService` to deploy@<toHost> presenting
// the stashed pre-rekey cert (paired with the still-present private key) instead
// of the current one. A non-zero exit confirms old certs are rejected after a
// CA rotation. We pass the identity + the old cert explicitly via -o so the
// spliced config's CertificateFile does not override it.
func sshOldCert(ctx context.Context, t *testing.T, fromService, toHost, instanceKey string) int {
	t.Helper()
	base := "/home/" + targetUser + "/.ssh"
	key := base + "/id_ed25519_" + instanceKey
	oldCert := base + "/old-cert.pub"
	sshCmd := fmt.Sprintf(
		"ssh -F /dev/null -o StrictHostKeyChecking=no -o PreferredAuthentications=publickey "+
			"-o PasswordAuthentication=no -o BatchMode=yes -o ConnectTimeout=10 "+
			"-o CertificateFile=%s -i %s %s@%s true",
		oldCert, key, targetUser, toHost)
	res := composeExec(ctx, t, targetUser, fromService, sshCmd)
	t.Logf("ssh(old cert) %s->%s exit=%d output=%q", fromService, toHost, res.exitCode, strings.TrimSpace(res.out))
	return res.exitCode
}
