//go:build e2e_systemd

// Package e2e (e2e_systemd tag) is a host-level end-to-end test for
// `certhold install`. Unlike the docker `e2e` suite, this test cannot run in a
// container — it installs and starts a real systemd unit on the host. It is
// gated behind its own `e2e_systemd` build tag so neither `go test ./...` nor
// `make e2e` ever compile or run it.
//
// It REQUIRES and MUTATES the host: a working systemd (`systemctl`) and
// passwordless sudo (`sudo -n`). It writes /etc/systemd/system/certhold.service,
// runs `systemctl enable --now certhold.service`, then tears all of that down
// via t.Cleanup. Run it with:
//
//	make e2e-systemd  # -> go test -tags e2e_systemd -count=1 -timeout 5m ./test/e2e/...
//
// The test skips (does not fail) when systemctl or passwordless sudo are
// unavailable, or when /etc/systemd/system/certhold.service already exists (so
// it never clobbers a real installation).
package e2e

import (
	"crypto/tls"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const systemdUnitPath = "/etc/systemd/system/certhold.service"

func TestSystemdInstall(t *testing.T) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		t.Skip("systemctl not found; skipping host systemd install e2e")
	}
	if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
		t.Skip("passwordless sudo (sudo -n) unavailable; skipping host systemd install e2e")
	}
	if _, err := os.Stat(systemdUnitPath); err == nil {
		t.Skipf("%s already exists; refusing to clobber an existing installation", systemdUnitPath)
	}

	curUser, err := user.Current()
	if err != nil {
		t.Fatalf("resolve current user: %v", err)
	}

	binDir, err := os.MkdirTemp("", "certhold-bin-")
	if err != nil {
		t.Fatalf("create binary temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(binDir) })
	if err := os.Chmod(binDir, 0o755); err != nil {
		t.Fatalf("chmod binary temp dir: %v", err)
	}
	binPath := filepath.Join(binDir, "certhold")

	build := exec.Command("go", "build", "-o", binPath, "./cmd/certhold")
	build.Dir = repoRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build certhold: %v\n%s", err, out)
	}
	if err := os.Chmod(binPath, 0o755); err != nil {
		t.Fatalf("chmod binary: %v", err)
	}

	dataDir, err := os.MkdirTemp("", "certhold-data-")
	if err != nil {
		t.Fatalf("create data temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dataDir) })
	dbPath := filepath.Join(dataDir, "state.db")

	t.Cleanup(func() {
		exec.Command("sudo", "-n", "systemctl", "disable", "--now", "certhold.service").Run()
		exec.Command("sudo", "-n", "rm", "-f", systemdUnitPath).Run()
		exec.Command("sudo", "-n", "systemctl", "daemon-reload").Run()
	})

	install := exec.Command("sudo", "-n", binPath, "install",
		"--addr", "127.0.0.1:18443",
		"--db", dbPath,
		"--data-dir", dataDir,
	)
	installOut, err := install.CombinedOutput()
	if err != nil {
		t.Fatalf("certhold install: %v\n%s", err, installOut)
	}
	out := string(installOut)
	if !strings.Contains(out, systemdUnitPath) {
		t.Fatalf("install output does not mention unit path %q:\n%s", systemdUnitPath, out)
	}
	if !strings.Contains(out, "certhold service installed and started") {
		t.Fatalf("install output missing success line:\n%s", out)
	}

	unit, err := os.ReadFile(systemdUnitPath)
	if err != nil {
		t.Fatalf("read installed unit %s: %v", systemdUnitPath, err)
	}
	wantUser := "User=" + curUser.Username
	if !strings.Contains(string(unit), wantUser) {
		t.Fatalf("unit file missing %q:\n%s", wantUser, unit)
	}

	deadline := time.Now().Add(30 * time.Second)
	var lastState string
	for time.Now().Before(deadline) {
		state, _ := exec.Command("systemctl", "is-active", "certhold").Output()
		lastState = strings.TrimSpace(string(state))
		if lastState == "active" {
			break
		}
		time.Sleep(time.Second)
	}
	if lastState != "active" {
		status, _ := exec.Command("systemctl", "status", "certhold", "--no-pager").CombinedOutput()
		t.Fatalf("certhold service never became active (last state %q):\n%s", lastState, status)
	}

	enabled, _ := exec.Command("systemctl", "is-enabled", "certhold").Output()
	if got := strings.TrimSpace(string(enabled)); got != "enabled" {
		t.Fatalf("systemctl is-enabled certhold = %q, want \"enabled\"", got)
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	var resp *http.Response
	httpDeadline := time.Now().Add(15 * time.Second)
	for {
		resp, err = client.Get("https://127.0.0.1:18443/")
		if err == nil {
			break
		}
		if time.Now().After(httpDeadline) {
			t.Fatalf("HTTPS GET https://127.0.0.1:18443/ failed: %v", err)
		}
		time.Sleep(time.Second)
	}
	resp.Body.Close()
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}
