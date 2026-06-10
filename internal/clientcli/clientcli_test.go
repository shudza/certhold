package clientcli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func needTools(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping", tool)
		}
	}
}

type bundle struct {
	key      string
	peer     string
	fleetRev int
	cert     []byte
	config   string
	cli      []byte
}

func (b bundle) tarGz(t *testing.T) []byte {
	t.Helper()
	manifest := fmt.Sprintf(
		"PEER_NAME=%s\nINSTANCE_KEY=%s\nFLEET_REV=%d\nCERT_SERIAL=7\nCLI_VERSION=%s\n",
		b.peer, b.key, b.fleetRev, Version)
	entries := []struct {
		name string
		mode int64
		data []byte
	}{
		{"id_ed25519_" + b.key + "-cert.pub", 0644, b.cert},
		{"config", 0644, []byte(b.config)},
		{"certhold-cli", 0755, b.cli},
		{"manifest", 0644, []byte(manifest)},
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     e.name,
			Mode:     e.mode,
			Size:     int64(len(e.data)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header %s: %v", e.name, err)
		}
		if _, err := tw.Write(e.data); err != nil {
			t.Fatalf("tar write %s: %v", e.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func newManager(t *testing.T, token string, tarGz []byte, rev string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/pull/"+token, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.Write(tarGz)
	})
	mux.HandleFunc("/pull/"+token+"/rev", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, rev)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func setupHome(t *testing.T) (home, sshDir string) {
	t.Helper()
	home = t.TempDir()
	sshDir = filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDir, 0700); err != nil {
		t.Fatal(err)
	}
	return home, sshDir
}

func writeConf(t *testing.T, sshDir, key, baseURL, token, peer, lastRev string) string {
	t.Helper()
	path := filepath.Join(sshDir, "certhold_"+key+".conf")
	content := "BASE_URL=" + baseURL + "\n" +
		"PULL_TOKEN=" + token + "\n" +
		"INSTANCE_KEY=" + key + "\n" +
		"PEER_NAME=" + peer + "\n" +
		"LAST_REV=" + lastRev + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func installScript(t *testing.T, dir string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, "certhold-cli")
	if err := os.WriteFile(path, data, 0755); err != nil {
		t.Fatal(err)
	}
	return path
}

func runCLI(t *testing.T, home, script string, args ...string) (output string, exitCode int) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("run %v: %v\n%s", args, err, out.String())
		}
		return out.String(), ee.ExitCode()
	}
	return out.String(), 0
}

func sentinelBlock(key, body string) string {
	return "# BEGIN certhold " + key + " v2\n" + body + "# END certhold " + key + " v2\n"
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestScriptSyntax(t *testing.T) {
	needTools(t, "bash")
	script := installScript(t, t.TempDir(), Script)
	out, err := exec.Command("bash", "-n", script).CombinedOutput()
	if err != nil {
		t.Fatalf("bash -n failed: %v\n%s", err, out)
	}
}

func TestVersionConstMatchesScript(t *testing.T) {
	re := regexp.MustCompile(`(?m)^CERTHOLD_CLI_VERSION="([^"]*)"$`)
	m := re.FindSubmatch(Script)
	if m == nil {
		t.Fatal("script has no CERTHOLD_CLI_VERSION line")
	}
	if string(m[1]) != Version {
		t.Fatalf("script CERTHOLD_CLI_VERSION=%q, Version const = %q", m[1], Version)
	}
}

func TestScriptStructure(t *testing.T) {
	text := strings.TrimSpace(string(Script))
	if !strings.HasSuffix(text, `main "$@"`) {
		t.Fatal(`script must end with a trailing main "$@" line`)
	}
	if !strings.Contains(text, "self_update \"$failed\"\n  exit \"$failed\"") {
		t.Fatal("self_update must be the last action of refresh, followed only by exit")
	}
	if !strings.Contains(text, "set -euo pipefail") {
		t.Fatal("script must set -euo pipefail")
	}
}

func TestRefreshAppliesBundleAndIsIdempotent(t *testing.T) {
	needTools(t, "bash", "curl")
	home, sshDir := setupHome(t)
	const key, token = "k1aaaa", "tok-refresh"

	userContent := "Host personal\n    User me\n\n"
	foreignBlock := sentinelBlock("otherkey", "Host *\n    IdentityFile ~/.ssh/id_ed25519_otherkey\n")
	staleBlock := "# BEGIN certhold " + key + " v1\nHost stale-old-content\n# END certhold " + key + " v1\n"
	cfgPath := filepath.Join(sshDir, "config")
	if err := os.WriteFile(cfgPath, []byte(userContent+foreignBlock+staleBlock), 0600); err != nil {
		t.Fatal(err)
	}

	newBlock := sentinelBlock(key, "Host *\n    CertificateFile ~/.ssh/id_ed25519_"+key+"-cert.pub\n    IdentityFile ~/.ssh/id_ed25519_"+key+"\n")
	certData := []byte("ssh-ed25519-cert-v01@openssh.com FAKECERTDATA test@peer\n")
	b := bundle{key: key, peer: "peer1", fleetRev: 7, cert: certData, config: newBlock, cli: Script}
	srv := newManager(t, token, b.tarGz(t), "7")

	confPath := writeConf(t, sshDir, key, srv.URL, token, "peer1", "3")
	script := installScript(t, sshDir, Script)

	out, code := runCLI(t, home, script, "refresh")
	if code != 0 {
		t.Fatalf("refresh exit %d:\n%s", code, out)
	}

	certPath := filepath.Join(sshDir, "id_ed25519_"+key+"-cert.pub")
	if got := mustReadFile(t, certPath); !bytes.Equal(got, certData) {
		t.Fatalf("cert content = %q, want %q", got, certData)
	}
	if info, err := os.Stat(certPath); err != nil || info.Mode().Perm() != 0644 {
		t.Fatalf("cert mode = %v (err %v), want 0644", info.Mode(), err)
	}

	cfg := string(mustReadFile(t, cfgPath))
	if !strings.Contains(cfg, userContent) {
		t.Fatalf("user content lost from config:\n%s", cfg)
	}
	if !strings.Contains(cfg, foreignBlock) {
		t.Fatalf("foreign sentinel block lost from config:\n%s", cfg)
	}
	if strings.Contains(cfg, "stale-old-content") {
		t.Fatalf("stale block not removed from config:\n%s", cfg)
	}
	if got := strings.Count(cfg, newBlock); got != 1 {
		t.Fatalf("new block appears %d times, want 1:\n%s", got, cfg)
	}

	conf := string(mustReadFile(t, confPath))
	if !strings.Contains(conf, "LAST_REV=7\n") {
		t.Fatalf("LAST_REV not rewritten:\n%s", conf)
	}
	for _, line := range []string{"BASE_URL=" + srv.URL, "PULL_TOKEN=" + token, "INSTANCE_KEY=" + key, "PEER_NAME=peer1"} {
		if !strings.Contains(conf, line+"\n") {
			t.Fatalf("conf line %q lost:\n%s", line, conf)
		}
	}

	cfgBefore := mustReadFile(t, cfgPath)
	certBefore := mustReadFile(t, certPath)
	confBefore := mustReadFile(t, confPath)
	scriptBefore := mustReadFile(t, script)

	out, code = runCLI(t, home, script, "refresh")
	if code != 0 {
		t.Fatalf("second refresh exit %d:\n%s", code, out)
	}
	if !bytes.Equal(mustReadFile(t, cfgPath), cfgBefore) {
		t.Fatal("config changed on second refresh")
	}
	if !bytes.Equal(mustReadFile(t, certPath), certBefore) {
		t.Fatal("cert changed on second refresh")
	}
	if !bytes.Equal(mustReadFile(t, confPath), confBefore) {
		t.Fatal("conf changed on second refresh")
	}
	if !bytes.Equal(mustReadFile(t, script), scriptBefore) {
		t.Fatal("script changed on second refresh")
	}

	leftovers, err := filepath.Glob(filepath.Join(sshDir, ".certhold-cli.*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("staging dirs not cleaned up: %v", leftovers)
	}
}

func TestRefreshSelfUpdateReplacesOutdatedCopy(t *testing.T) {
	needTools(t, "bash", "curl")
	home, sshDir := setupHome(t)
	const key, token = "k2bbbb", "tok-selfupdate"

	b := bundle{
		key: key, peer: "peer2", fleetRev: 4,
		cert:   []byte("cert-bytes\n"),
		config: sentinelBlock(key, "Host *\n    CertificateFile ~/.ssh/id_ed25519_"+key+"-cert.pub\n"),
		cli:    Script,
	}
	srv := newManager(t, token, b.tarGz(t), "4")
	confPath := writeConf(t, sshDir, key, srv.URL, token, "peer2", "1")

	doctored := append(append([]byte{}, Script...), []byte("\n# doctored: pretend old version\n")...)
	script := installScript(t, sshDir, doctored)

	out, code := runCLI(t, home, script, "refresh")
	if code != 0 {
		t.Fatalf("refresh exit %d:\n%s", code, out)
	}
	if !strings.Contains(out, "self-updated") {
		t.Fatalf("expected self-update note in output:\n%s", out)
	}
	if got := mustReadFile(t, script); !bytes.Equal(got, Script) {
		t.Fatal("installed script not replaced with bundled version")
	}
	info, err := os.Stat(script)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatalf("script mode = %v (err %v), want 0755", info.Mode(), err)
	}
	if !strings.Contains(string(mustReadFile(t, confPath)), "LAST_REV=4\n") {
		t.Fatal("refresh did not run before self-update (LAST_REV not rewritten)")
	}
	cfgInfo, err := os.Stat(filepath.Join(sshDir, "config"))
	if err != nil || cfgInfo.Mode().Perm() != 0600 {
		t.Fatalf("created config mode = %v (err %v), want 0600", cfgInfo.Mode(), err)
	}
}

func TestRefreshIsolatesFailingInstance(t *testing.T) {
	needTools(t, "bash", "curl")
	home, sshDir := setupHome(t)
	const goodKey, badKey, token = "k3good", "k3bad", "tok-iso"

	b := bundle{
		key: goodKey, peer: "peer3", fleetRev: 2,
		cert:   []byte("good-cert\n"),
		config: sentinelBlock(goodKey, "Host *\n    CertificateFile ~/.ssh/id_ed25519_"+goodKey+"-cert.pub\n"),
		cli:    Script,
	}
	srv := newManager(t, token, b.tarGz(t), "2")
	writeConf(t, sshDir, badKey, "http://127.0.0.1:1", "no-such-token", "peer3", "0")
	goodConf := writeConf(t, sshDir, goodKey, srv.URL, token, "peer3", "0")
	script := installScript(t, sshDir, Script)

	out, code := runCLI(t, home, script, "refresh")
	if code == 0 {
		t.Fatalf("refresh with a failing instance must exit non-zero:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(sshDir, "id_ed25519_"+goodKey+"-cert.pub")); err != nil {
		t.Fatalf("good instance not refreshed: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(sshDir, "id_ed25519_"+badKey+"-cert.pub")); err == nil {
		t.Fatal("failing instance unexpectedly produced a cert")
	}
	if !strings.Contains(string(mustReadFile(t, goodConf)), "LAST_REV=2\n") {
		t.Fatal("good instance LAST_REV not rewritten")
	}

	out, code = runCLI(t, home, script, "refresh", "--instance", goodKey)
	if code != 0 {
		t.Fatalf("refresh --instance %s exit %d:\n%s", goodKey, code, out)
	}
}

func TestStatusVerdicts(t *testing.T) {
	needTools(t, "bash", "curl")
	const key, token = "k4cccc", "tok-status"

	cases := []struct {
		name    string
		lastRev string
		rev     string
		close   bool
		want    string
	}{
		{"up-to-date", "5", "5", false, "up-to-date"},
		{"stale", "1", "5", false, "stale"},
		{"unreachable", "5", "5", true, "manager unreachable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home, sshDir := setupHome(t)
			srv := newManager(t, token, []byte("unused"), tc.rev)
			writeConf(t, sshDir, key, srv.URL, token, "peer4", tc.lastRev)
			if err := os.WriteFile(filepath.Join(sshDir, "id_ed25519_"+key+"-cert.pub"), []byte("not a real cert\n"), 0644); err != nil {
				t.Fatal(err)
			}
			if tc.close {
				srv.Close()
			}
			script := installScript(t, sshDir, Script)
			out, code := runCLI(t, home, script, "status")
			if code != 0 {
				t.Fatalf("status exit %d:\n%s", code, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("status output missing %q:\n%s", tc.want, out)
			}
			for _, want := range []string{key, "peer4", "local rev:  " + tc.lastRev} {
				if !strings.Contains(out, want) {
					t.Fatalf("status output missing %q:\n%s", want, out)
				}
			}
		})
	}
}

func TestUsageAndUnknownCommand(t *testing.T) {
	needTools(t, "bash")
	home, sshDir := setupHome(t)
	script := installScript(t, sshDir, Script)

	out, code := runCLI(t, home, script, "--help")
	if code != 0 || !strings.Contains(out, "Usage:") {
		t.Fatalf("--help exit %d:\n%s", code, out)
	}
	out, code = runCLI(t, home, script)
	if code != 2 || !strings.Contains(out, "Usage:") {
		t.Fatalf("no args: exit %d, want 2 with usage:\n%s", code, out)
	}
	out, code = runCLI(t, home, script, "bogus")
	if code != 2 {
		t.Fatalf("unknown command: exit %d, want 2:\n%s", code, out)
	}
}
