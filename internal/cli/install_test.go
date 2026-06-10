package cli

import (
	"bytes"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func mustContain(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("output missing %q\n--- full output ---\n%s", want, got)
	}
}

func newTestInstallCmd(args ...string) (*bytes.Buffer, error) {
	root := NewRootCmd()
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs(append([]string{"install"}, args...))
	err := root.Execute()
	return out, err
}

func withInstallStubs(t *testing.T) {
	t.Helper()
	origSysctl := installSystemctlFn
	origGeteuid := installGeteuidFn
	origExec := installExecutableFn
	origLookup := installLookupUserFn
	origPath := installUnitPath
	t.Cleanup(func() {
		installSystemctlFn = origSysctl
		installGeteuidFn = origGeteuid
		installExecutableFn = origExec
		installLookupUserFn = origLookup
		installUnitPath = origPath
	})
	installExecutableFn = func() (string, error) { return "/opt/certhold/bin/certhold", nil }
}

func TestInstallPrintDefault(t *testing.T) {
	withInstallStubs(t)
	t.Setenv("SUDO_USER", "")
	installLookupUserFn = func(name string) (*user.User, error) {
		return &user.User{Username: name, HomeDir: "/home/" + name}, nil
	}

	cur, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}

	out, err := newTestInstallCmd("--print")
	if err != nil {
		t.Fatalf("install --print: %v", err)
	}
	got := out.String()

	wantHome := "/home/" + cur.Username
	mustContain(t, got, "[Unit]\nDescription=Certhold SSH enrollment endpoint (certhold serve)\nAfter=network-online.target\nWants=network-online.target\n")
	mustContain(t, got, "[Service]\nType=simple\n")
	mustContain(t, got, "User="+cur.Username+"\n")
	mustContain(t, got, "ExecStart=/opt/certhold/bin/certhold serve --addr :8443 --db "+filepath.Join(wantHome, ".certhold", "state.db")+" --data-dir "+filepath.Join(wantHome, ".certhold")+"\n")
	mustContain(t, got, "Restart=on-failure\nRestartSec=2\nNoNewPrivileges=true\n")
	mustContain(t, got, "[Install]\nWantedBy=multi-user.target\n")
}

func TestInstallPrintWithAddrAndTLS(t *testing.T) {
	withInstallStubs(t)
	t.Setenv("SUDO_USER", "")
	installLookupUserFn = func(name string) (*user.User, error) {
		return &user.User{Username: name, HomeDir: "/home/" + name}, nil
	}

	out, err := newTestInstallCmd("--print", "--addr", "0.0.0.0:9999", "--tls-cert", "/etc/cert.pem", "--tls-key", "/etc/key.pem")
	if err != nil {
		t.Fatalf("install --print: %v", err)
	}
	got := out.String()
	mustContain(t, got, "--addr 0.0.0.0:9999")
	mustContain(t, got, "--tls-cert /etc/cert.pem --tls-key /etc/key.pem\n")
}

func TestInstallSudoUserHomeDerived(t *testing.T) {
	withInstallStubs(t)
	t.Setenv("SUDO_USER", "alice")
	installLookupUserFn = func(name string) (*user.User, error) {
		if name != "alice" {
			t.Fatalf("expected lookup of alice, got %q", name)
		}
		return &user.User{Username: "alice", HomeDir: "/home/alice"}, nil
	}

	out, err := newTestInstallCmd("--print")
	if err != nil {
		t.Fatalf("install --print: %v", err)
	}
	got := out.String()
	mustContain(t, got, "User=alice\n")
	mustContain(t, got, "--db /home/alice/.certhold/state.db --data-dir /home/alice/.certhold\n")
}

func TestInstallExplicitDBAndDataDirRespected(t *testing.T) {
	withInstallStubs(t)
	t.Setenv("SUDO_USER", "alice")
	installLookupUserFn = func(name string) (*user.User, error) {
		t.Fatalf("user.Lookup should not be called when both flags are explicit")
		return nil, nil
	}

	root := NewRootCmd()
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"--db", "/srv/db.sqlite", "--data-dir", "/srv/data", "install", "--print"})
	if err := root.Execute(); err != nil {
		t.Fatalf("install --print: %v", err)
	}
	got := out.String()
	mustContain(t, got, "--db /srv/db.sqlite --data-dir /srv/data\n")
}

func TestInstallTLSPairingError(t *testing.T) {
	withInstallStubs(t)
	t.Setenv("SUDO_USER", "")
	installLookupUserFn = func(name string) (*user.User, error) {
		return &user.User{Username: name, HomeDir: "/home/" + name}, nil
	}

	_, err := newTestInstallCmd("--print", "--tls-cert", "/etc/cert.pem")
	if err == nil {
		t.Fatal("expected error for tls-cert without tls-key")
	}
	if !strings.Contains(err.Error(), "--tls-cert and --tls-key must be provided together") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstallNonRootError(t *testing.T) {
	withInstallStubs(t)
	t.Setenv("SUDO_USER", "")
	installLookupUserFn = func(name string) (*user.User, error) {
		return &user.User{Username: name, HomeDir: "/home/" + name}, nil
	}
	installGeteuidFn = func() int { return 1000 }
	var calls [][]string
	installSystemctlFn = func(args ...string) error {
		calls = append(calls, args)
		return nil
	}

	_, err := newTestInstallCmd()
	if err == nil {
		t.Fatal("expected root-required error")
	}
	if !strings.Contains(err.Error(), "install must run as root: try 'sudo certhold install'") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("systemctl must not be called as non-root, got %v", calls)
	}
}

func TestInstallSystemctlCallOrderAndChanged(t *testing.T) {
	withInstallStubs(t)
	t.Setenv("SUDO_USER", "")
	installLookupUserFn = func(name string) (*user.User, error) {
		return &user.User{Username: name, HomeDir: "/home/" + name}, nil
	}
	installGeteuidFn = func() int { return 0 }
	installUnitPath = filepath.Join(t.TempDir(), "certhold.service")

	var calls [][]string
	installSystemctlFn = func(args ...string) error {
		calls = append(calls, args)
		return nil
	}

	out, err := newTestInstallCmd()
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	got := out.String()
	mustContain(t, got, "Changed files:")
	mustContain(t, got, "  ~ "+installUnitPath)
	mustContain(t, got, "certhold service installed and started (check: systemctl status certhold)")

	if len(calls) != 2 {
		t.Fatalf("expected 2 systemctl calls, got %v", calls)
	}
	if strings.Join(calls[0], " ") != "daemon-reload" {
		t.Fatalf("first call must be daemon-reload, got %v", calls[0])
	}
	if strings.Join(calls[1], " ") != "enable --now certhold.service" {
		t.Fatalf("second call must be enable --now certhold.service, got %v", calls[1])
	}
}

func TestInstallUnchangedReporting(t *testing.T) {
	withInstallStubs(t)
	t.Setenv("SUDO_USER", "")
	installLookupUserFn = func(name string) (*user.User, error) {
		return &user.User{Username: name, HomeDir: "/home/" + name}, nil
	}
	installGeteuidFn = func() int { return 0 }
	installUnitPath = filepath.Join(t.TempDir(), "certhold.service")
	installSystemctlFn = func(args ...string) error { return nil }

	if _, err := newTestInstallCmd(); err != nil {
		t.Fatalf("first install: %v", err)
	}
	out, err := newTestInstallCmd()
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	got := out.String()
	mustContain(t, got, "  = "+installUnitPath)
	if strings.Contains(got, "  ~ "+installUnitPath) {
		t.Fatalf("second install should report unchanged, got:\n%s", got)
	}
}
