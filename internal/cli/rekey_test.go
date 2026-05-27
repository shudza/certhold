package cli

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/sshpush"
)

type rekeyMockCall struct {
	host    string
	op      string
	path    string
	content []byte
}

type rekeyRecorder struct {
	mu       sync.Mutex
	calls    []rekeyMockCall
	failOn   map[string]error
	readData map[string][]byte
}

func (r *rekeyRecorder) snapshot() []rekeyMockCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]rekeyMockCall, len(r.calls))
	copy(out, r.calls)
	return out
}

type rekeyMockPusher struct {
	host string
	rec  *rekeyRecorder
}

func (m *rekeyMockPusher) WriteFileAtomic(ctx context.Context, p string, content []byte, mode fs.FileMode) error {
	m.rec.mu.Lock()
	if err, ok := m.rec.failOn["write:"+m.host+":"+p]; ok {
		m.rec.mu.Unlock()
		return err
	}
	m.rec.calls = append(m.rec.calls, rekeyMockCall{host: m.host, op: "write", path: p, content: append([]byte(nil), content...)})
	m.rec.mu.Unlock()
	return nil
}

func (m *rekeyMockPusher) ReadFile(ctx context.Context, p string) ([]byte, error) {
	m.rec.mu.Lock()
	defer m.rec.mu.Unlock()
	m.rec.calls = append(m.rec.calls, rekeyMockCall{host: m.host, op: "read", path: p})
	if m.rec.readData != nil {
		if data, ok := m.rec.readData[m.host+":"+p]; ok {
			return append([]byte(nil), data...), nil
		}
	}
	return nil, nil
}

func (m *rekeyMockPusher) ReloadSSHD(ctx context.Context) error {
	m.rec.mu.Lock()
	defer m.rec.mu.Unlock()
	m.rec.calls = append(m.rec.calls, rekeyMockCall{host: m.host, op: "reload"})
	return nil
}

func (m *rekeyMockPusher) VerifyHealth(ctx context.Context) error {
	m.rec.mu.Lock()
	defer m.rec.mu.Unlock()
	m.rec.calls = append(m.rec.calls, rekeyMockCall{host: m.host, op: "verify"})
	return nil
}

func (m *rekeyMockPusher) Close() error { return nil }

func setupRekeyEnv(t *testing.T, failOn map[string]error) (dataDir, dbPath, hostname string, rec *rekeyRecorder, cleanup func()) {
	t.Helper()
	t.Setenv("CERTHOLD_CA_PASSPHRASE", "test-ca-pw")
	t.Setenv("CERTHOLD_PEER_PASSPHRASE", "test-peer-pw")
	dir := t.TempDir()
	dataDir = filepath.Join(dir, "data")
	dbPath = filepath.Join(dir, "state.db")
	hostname = "mgr"

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}

	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "init", "--hostname", hostname, "--mode", "root"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("init: %v\n%s", err, buf.String())
	}

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	ctx := context.Background()
	for _, name := range []string{"alpha", "beta"} {
		_, pubAuth, sshPub, err := ca.GeneratePeerKey()
		if err != nil {
			t.Fatalf("GeneratePeerKey %s: %v", name, err)
		}
		fp := ssh.FingerprintSHA256(sshPub)
		if err := d.InsertPeer(ctx, name, 100, fp, pubAuth); err != nil {
			t.Fatalf("InsertPeer %s: %v", name, err)
		}
		if err := d.EnsureGroup(ctx, "infra"); err != nil {
			t.Fatalf("EnsureGroup infra: %v", err)
		}
		if err := d.SetPeerGroups(ctx, name, []string{"infra"}); err != nil {
			t.Fatalf("SetPeerGroups %s: %v", name, err)
		}
	}

	rec = &rekeyRecorder{failOn: failOn}
	if rec.failOn == nil {
		rec.failOn = map[string]error{}
	}
	origDial := rekeyDial
	rekeyDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		rec.mu.Lock()
		err, ok := rec.failOn["dial:"+host]
		rec.mu.Unlock()
		if ok {
			return nil, err
		}
		return &rekeyMockPusher{host: host, rec: rec}, nil
	}
	cleanup = func() { rekeyDial = origDial }
	return dataDir, dbPath, hostname, rec, cleanup
}

func runRekeyCmd(t *testing.T, dataDir, dbPath, hostname string) (string, string, error) {
	t.Helper()
	cmd := NewRootCmd()
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetArgs([]string{"--data-dir", dataDir, "--db", dbPath, "rekey", "--hostname", hostname})
	err := cmd.ExecuteContext(context.Background())
	return out.String(), errBuf.String(), err
}

func TestRekeyHappyPath(t *testing.T) {
	dataDir, dbPath, hostname, rec, cleanup := setupRekeyEnv(t, nil)
	defer cleanup()

	caDir := filepath.Join(dataDir, "ca")
	oldCAPub, err := os.ReadFile(filepath.Join(caDir, "ca.pub"))
	if err != nil {
		t.Fatalf("read old ca.pub: %v", err)
	}

	d0, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	prevSerials := map[string]uint64{}
	for _, name := range []string{"alpha", "beta", hostname} {
		p, err := d0.GetPeer(context.Background(), name)
		if err != nil {
			t.Fatalf("GetPeer %s: %v", name, err)
		}
		prevSerials[name] = p.Serial
	}
	d0.Close()

	stdout, stderr, err := runRekeyCmd(t, dataDir, dbPath, hostname)
	if err != nil {
		t.Fatalf("rekey: err=%v\nstderr:%s\nstdout:%s", err, stderr, stdout)
	}

	calls := rec.snapshot()
	type opEvent struct {
		host string
		op   string
		path string
	}
	var perHost = map[string][]opEvent{}
	for _, c := range calls {
		perHost[c.host] = append(perHost[c.host], opEvent{c.host, c.op, c.path})
	}

	for _, h := range []string{"alpha", "beta"} {
		evs, ok := perHost[h]
		if !ok {
			t.Errorf("no calls for host %s", h)
			continue
		}
		want := []opEvent{
			{h, "write", "/etc/ssh/ca.pub"},
			{h, "write", "/etc/ssh/peer_ed25519-cert.pub"},
			{h, "reload", ""},
			{h, "verify", ""},
		}
		if len(evs) != len(want) {
			t.Errorf("host %s: got %d ops, want %d: %+v", h, len(evs), len(want), evs)
			continue
		}
		for i := range want {
			if evs[i] != want[i] {
				t.Errorf("host %s op[%d] = %+v, want %+v", h, i, evs[i], want[i])
			}
		}
	}

	if _, ok := perHost[hostname]; ok {
		t.Errorf("certhold's own peer should not receive pushes; got %v", perHost[hostname])
	}

	newCAPub, err := os.ReadFile(filepath.Join(caDir, "ca.pub"))
	if err != nil {
		t.Fatalf("read new ca.pub: %v", err)
	}
	if bytes.Equal(newCAPub, oldCAPub) {
		t.Error("ca.pub bytes did not change after rekey")
	}

	for _, c := range calls {
		if c.op == "write" && c.path == "/etc/ssh/ca.pub" {
			if !bytes.Equal(c.content, newCAPub) {
				t.Errorf("ca.pub pushed to %s does not match new ca.pub", c.host)
			}
		}
	}

	// v2 manager self files: no ca.pub; the new CA's trust lives in the v2
	// authorized_keys cert-authority line, and the cert is namespaced.
	key := instanceKeyFromDBPkg(t, dbPath)
	selfBase := filepath.Join(dataDir, "self", "root", ".ssh")
	selfAK, err := os.ReadFile(filepath.Join(selfBase, "authorized_keys"))
	if err != nil {
		t.Fatalf("read self authorized_keys: %v", err)
	}
	if !bytes.Contains(selfAK, bytes.TrimRight(newCAPub, "\n")) {
		t.Error("self authorized_keys does not carry the new CA pubkey")
	}

	selfCert, err := os.ReadFile(filepath.Join(selfBase, "id_ed25519_"+key+"-cert.pub"))
	if err != nil {
		t.Fatalf("read self cert: %v", err)
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey(selfCert)
	if err != nil {
		t.Fatalf("parse self cert: %v", err)
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		t.Fatalf("self cert not a certificate: %T", pk)
	}
	caPk, _, _, _, err := ssh.ParseAuthorizedKey(newCAPub)
	if err != nil {
		t.Fatalf("parse new ca pub: %v", err)
	}
	if !bytes.Equal(cert.SignatureKey.Marshal(), caPk.Marshal()) {
		t.Error("self cert not signed by new CA")
	}
	if cert.KeyId != hostname {
		t.Errorf("self cert KeyId = %q, want %q", cert.KeyId, hostname)
	}
	gotPrincipals := append([]string(nil), cert.ValidPrincipals...)
	sort.Strings(gotPrincipals)
	wantPrincipals := []string{hostname, "manager"}
	sort.Strings(wantPrincipals)
	if !equalStr(gotPrincipals, wantPrincipals) {
		t.Errorf("self principals = %v, want %v", gotPrincipals, wantPrincipals)
	}

	for _, c := range calls {
		if c.op == "write" && c.path == "/etc/ssh/peer_ed25519-cert.pub" {
			pk, _, _, _, err := ssh.ParseAuthorizedKey(c.content)
			if err != nil {
				t.Errorf("parse cert for %s: %v", c.host, err)
				continue
			}
			peerCert, ok := pk.(*ssh.Certificate)
			if !ok {
				t.Errorf("cert for %s not a certificate", c.host)
				continue
			}
			if !bytes.Equal(peerCert.SignatureKey.Marshal(), caPk.Marshal()) {
				t.Errorf("cert for %s not signed by new CA", c.host)
			}
			if peerCert.KeyId != c.host {
				t.Errorf("KeyId for %s = %q", c.host, peerCert.KeyId)
			}
		}
	}

	d2, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer d2.Close()
	for _, name := range []string{"alpha", "beta", hostname} {
		p, err := d2.GetPeer(context.Background(), name)
		if err != nil {
			t.Fatalf("GetPeer %s: %v", name, err)
		}
		if p.Serial == prevSerials[name] {
			t.Errorf("serial for %s unchanged: %d", name, p.Serial)
		}
	}

	ver, err := d2.ActiveCAVersion(context.Background())
	if err != nil {
		t.Fatalf("ActiveCAVersion: %v", err)
	}
	if ver != 1 {
		t.Errorf("active ca version = %d, want 1", ver)
	}

	if _, err := os.Stat(filepath.Join(dataDir, "ca.next")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("ca.next should be gone after swap, got err=%v", err)
	}
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatalf("ReadDir dataDir: %v", err)
	}
	foundOld := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "ca.old.") {
			foundOld = true
			break
		}
	}
	if !foundOld {
		t.Error("expected ca.old.<timestamp> directory after rekey")
	}

	if stdout == "" {
		t.Error("expected summary output")
	}
}

func TestRekeyEncryptedCA_RotatedKeyUnlockableWithOriginalPassphrase(t *testing.T) {
	const caPW = "test-ca-pw"
	dataDir, dbPath, hostname, _, cleanup := setupRekeyEnv(t, nil)
	defer cleanup()

	caDir := filepath.Join(dataDir, "ca")
	if enc, err := caKeyEncrypted(caDir); err != nil {
		t.Fatalf("caKeyEncrypted: %v", err)
	} else if !enc {
		t.Fatal("test precondition: CA key should be encrypted after env-injected init")
	}

	_, stderr, err := runRekeyCmd(t, dataDir, dbPath, hostname)
	if err != nil {
		t.Fatalf("rekey: err=%v stderr=%s", err, stderr)
	}

	if enc, err := caKeyEncrypted(caDir); err != nil {
		t.Fatalf("caKeyEncrypted after rekey: %v", err)
	} else if !enc {
		t.Fatal("rotated CA key is not encrypted; default rekey must preserve encryption")
	}

	_, err = ca.LoadWithPassphrase(caDir, func() ([]byte, error) {
		return []byte(caPW), nil
	})
	if err != nil {
		t.Fatalf("rotated CA not unlockable with original passphrase: %v "+
			"(B1: memoized unlocker was zeroed in place, so the new CA was encrypted with zeros)", err)
	}
}

func TestRekeyRotatePassphrase_NewUnlocksOldFails(t *testing.T) {
	const oldPW = "test-ca-pw"
	const newPW = "rotated-ca-pw"
	dataDir, dbPath, hostname, _, cleanup := setupRekeyEnv(t, nil)
	defer cleanup()

	caDir := filepath.Join(dataDir, "ca")
	if enc, err := caKeyEncrypted(caDir); err != nil {
		t.Fatalf("caKeyEncrypted: %v", err)
	} else if !enc {
		t.Fatal("test precondition: CA key should be encrypted after env-injected init")
	}

	origPrompt := promptNewCAPassphrase
	var newPromptCalls int
	promptNewCAPassphrase = func() ([]byte, error) {
		newPromptCalls++
		return []byte(newPW), nil
	}
	defer func() { promptNewCAPassphrase = origPrompt }()

	cmd := NewRootCmd()
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetArgs([]string{"--data-dir", dataDir, "--db", dbPath, "rekey", "--hostname", hostname, "--rotate-passphrase"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("rekey --rotate-passphrase: err=%v stderr=%s stdout=%s", err, errBuf.String(), out.String())
	}

	if newPromptCalls == 0 {
		t.Fatal("expected the new-passphrase prompt to be invoked in rotate mode")
	}

	if enc, err := caKeyEncrypted(caDir); err != nil {
		t.Fatalf("caKeyEncrypted after rekey: %v", err)
	} else if !enc {
		t.Fatal("rotated CA key is not encrypted; --rotate-passphrase must still encrypt")
	}

	if _, err := ca.LoadWithPassphrase(caDir, func() ([]byte, error) {
		return []byte(newPW), nil
	}); err != nil {
		t.Fatalf("rotated CA not unlockable with the NEW passphrase: %v", err)
	}

	if _, err := ca.LoadWithPassphrase(caDir, func() ([]byte, error) {
		return []byte(oldPW), nil
	}); err == nil {
		t.Fatal("rotated CA unlocked with the OLD passphrase; --rotate-passphrase did not change the key encryption")
	}
}

func TestRekeyFailureAborts(t *testing.T) {
	dataDir, dbPath, hostname, rec, cleanup := setupRekeyEnv(t, map[string]error{
		"write:beta:/etc/ssh/ca.pub": errors.New("boom"),
	})
	defer cleanup()

	caDir := filepath.Join(dataDir, "ca")
	oldCAPub, err := os.ReadFile(filepath.Join(caDir, "ca.pub"))
	if err != nil {
		t.Fatalf("read old ca.pub: %v", err)
	}
	key := instanceKeyFromDBPkg(t, dbPath)
	selfBase := filepath.Join(dataDir, "self", "root", ".ssh")
	selfCertBefore, err := os.ReadFile(filepath.Join(selfBase, "id_ed25519_"+key+"-cert.pub"))
	if err != nil {
		t.Fatalf("read self cert: %v", err)
	}
	selfAKBefore, err := os.ReadFile(filepath.Join(selfBase, "authorized_keys"))
	if err != nil {
		t.Fatalf("read self authorized_keys: %v", err)
	}

	_, stderr, err := runRekeyCmd(t, dataDir, dbPath, hostname)
	if err == nil {
		t.Fatal("expected error from rekey")
	}
	if !strings.Contains(stderr, "aborted") {
		t.Errorf("expected 'aborted' in stderr, got: %s", stderr)
	}

	caPubAfter, err := os.ReadFile(filepath.Join(caDir, "ca.pub"))
	if err != nil {
		t.Fatalf("read ca.pub after: %v", err)
	}
	if !bytes.Equal(caPubAfter, oldCAPub) {
		t.Error("CA was rotated despite failure; expected old CA to remain in place")
	}

	selfCertAfter, err := os.ReadFile(filepath.Join(selfBase, "id_ed25519_"+key+"-cert.pub"))
	if err != nil {
		t.Fatalf("read self cert after: %v", err)
	}
	if !bytes.Equal(selfCertAfter, selfCertBefore) {
		t.Error("self cert was modified despite failure")
	}
	selfAKAfter, err := os.ReadFile(filepath.Join(selfBase, "authorized_keys"))
	if err != nil {
		t.Fatalf("read self authorized_keys after: %v", err)
	}
	if !bytes.Equal(selfAKAfter, selfAKBefore) {
		t.Error("self authorized_keys was modified despite failure")
	}

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	if _, err := d.ActiveCAVersion(context.Background()); !errors.Is(err, db.ErrNoActiveCA) {
		t.Errorf("expected ErrNoActiveCA after failed rekey, got: %v", err)
	}

	calls := rec.snapshot()
	for _, c := range calls {
		if c.host == hostname {
			t.Errorf("certhold's own peer should never receive remote pushes: %+v", c)
		}
	}
}

func TestRekeyUserModePeer_RewritesAuthorizedKeys_NoReload(t *testing.T) {
	t.Setenv("CERTHOLD_CA_PASSPHRASE", "test-ca-pw")
	t.Setenv("CERTHOLD_PEER_PASSPHRASE", "test-peer-pw")
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	dbPath := filepath.Join(dir, "state.db")
	hostname := "mgr"
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "init", "--hostname", hostname, "--mode", "root"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("init: %v\n%s", err, buf.String())
	}

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	ctx := context.Background()
	_, pubAuth, _, _ := ca.GeneratePeerKey()
	if err := d.InsertPeerWithMode(ctx, "vmU", 100, "fp-u", pubAuth, db.ModeUser, "alice", 1); err != nil {
		t.Fatalf("InsertPeerWithMode: %v", err)
	}
	_ = d.EnsureGroup(ctx, "infra")
	_ = d.SetPeerGroups(ctx, "vmU", []string{"infra"})
	_ = d.SetPeerAllowedGroups(ctx, "vmU", []string{"infra"})
	d.Close()

	rec := &rekeyRecorder{}
	origDial := rekeyDial
	rekeyDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		return &rekeyMockPusher{host: host, rec: rec}, nil
	}
	defer func() { rekeyDial = origDial }()

	cmd2 := NewRootCmd()
	var out, errBuf bytes.Buffer
	cmd2.SetOut(&out)
	cmd2.SetErr(&errBuf)
	cmd2.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "rekey", "--hostname", hostname})
	if err := cmd2.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("rekey: err=%v stderr=%s stdout=%s", err, errBuf.String(), out.String())
	}

	calls := rec.snapshot()
	gotAK := false
	gotCert := false
	gotReload := false
	wantAKPath := "/home/alice/.ssh/authorized_keys"
	wantCertPath := "/home/alice/.ssh/id_ed25519-cert.pub"
	for _, c := range calls {
		if c.host != "vmU" {
			continue
		}
		if c.op == "write" && c.path == wantAKPath {
			gotAK = true
			if !strings.Contains(string(c.content), `cert-authority,principals="manager,infra"`) {
				t.Errorf("authorized_keys content wrong: %q", c.content)
			}
		}
		if c.op == "write" && c.path == wantCertPath {
			gotCert = true
		}
		if c.op == "reload" {
			gotReload = true
		}
	}
	if !gotAK {
		t.Errorf("missing user-mode AK write to %s; calls=%+v", wantAKPath, calls)
	}
	if !gotCert {
		t.Errorf("missing user-mode cert write to %s; calls=%+v", wantCertPath, calls)
	}
	if gotReload {
		t.Errorf("user-mode rekey must not call ReloadSSHD; calls=%+v", calls)
	}
}

func instanceKeyFromDBPkg(t *testing.T, dbPath string) string {
	t.Helper()
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	k, ok, err := d.GetMeta(context.Background(), db.MetaInstanceKey)
	if err != nil || !ok {
		t.Fatalf("GetMeta: ok=%v err=%v", ok, err)
	}
	return k
}

func equalStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestRekeyV2RootPeer_RewritesAuthorizedKeys_NoReload exercises CA rekey against
// a v2 root peer: its namespaced cert and the swapped cert-authority line are
// pushed to /root/.ssh, with no sshd reload.
func TestRekeyV2RootPeer_RewritesAuthorizedKeys_NoReload(t *testing.T) {
	t.Setenv("CERTHOLD_CA_PASSPHRASE", "test-ca-pw")
	t.Setenv("CERTHOLD_PEER_PASSPHRASE", "test-peer-pw")
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	dbPath := filepath.Join(dir, "state.db")
	hostname := "mgr"
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--db", dbPath, "--data-dir", dataDir, "init", "--hostname", hostname, "--mode", "root"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("init: %v\n%s", err, buf.String())
	}

	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	ctx := context.Background()
	key, _, _ := d.GetMeta(ctx, db.MetaInstanceKey)
	_, pubAuth, _, _ := ca.GeneratePeerKey()
	if err := d.InsertPeerWithMode(ctx, "vmV2", 100, "fp-v2", pubAuth, db.ModeRoot, "", 2); err != nil {
		t.Fatalf("InsertPeerWithMode: %v", err)
	}
	_ = d.EnsureGroup(ctx, "infra")
	_ = d.SetPeerGroups(ctx, "vmV2", []string{"infra"})
	_ = d.SetPeerAllowedGroups(ctx, "vmV2", []string{"infra"})
	d.Close()

	rec := &rekeyRecorder{}
	origDial := rekeyDial
	rekeyDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
		return &rekeyMockPusher{host: host, rec: rec}, nil
	}
	defer func() { rekeyDial = origDial }()

	if _, stderr, err := runRekeyCmd(t, dataDir, dbPath, hostname); err != nil {
		t.Fatalf("rekey: err=%v stderr=%s", err, stderr)
	}

	gotAK, gotCert, gotReload := false, false, false
	for _, c := range rec.snapshot() {
		if c.host != "vmV2" {
			continue
		}
		switch {
		case c.op == "write" && c.path == "/root/.ssh/authorized_keys":
			gotAK = true
		case c.op == "write" && c.path == "/root/.ssh/id_ed25519_"+key+"-cert.pub":
			gotCert = true
		case c.op == "reload":
			gotReload = true
		}
	}
	if !gotAK {
		t.Errorf("v2 root rekey must rewrite /root/.ssh/authorized_keys")
	}
	if !gotCert {
		t.Errorf("v2 root rekey must push the namespaced cert")
	}
	if gotReload {
		t.Errorf("v2 root rekey must NOT reload sshd")
	}
}
