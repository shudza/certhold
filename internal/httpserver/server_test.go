package httpserver

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
)

type testEnv struct {
	srv *httptest.Server
	db  *db.DB
	ca  *ca.CA
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()
	tempDir := t.TempDir()
	caObj, err := ca.Generate(filepath.Join(tempDir, "ca"))
	if err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	d, err := db.Open(filepath.Join(tempDir, "state.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	handler := New(d, caObj, "certhold.test")
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return &testEnv{srv: srv, db: d, ca: caObj}
}

func extractTarball(t *testing.T, body []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar.Next: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		out[hdr.Name] = data
	}
	return out
}

func TestEnrollSuccess(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	const tok = "test-token-vm1"
	if err := env.db.InsertToken(ctx, tok, "vm1", "infra,databases"); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}

	resp, err := http.Get(env.srv.URL + "/enroll/" + tok)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/gzip" {
		t.Errorf("Content-Type = %q, want application/gzip", ct)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	entries := extractTarball(t, body)

	expectedNames := []string{
		"etc/ssh/peer_ed25519",
		"etc/ssh/peer_ed25519-cert.pub",
		"etc/ssh/ca.pub",
		"etc/ssh/krl",
		"etc/ssh/sshd_config.d/certhold.conf",
		"etc/ssh/auth_principals/root",
		"etc/ssh/ca_known_hosts",
		"etc/ssh/ssh_config.d/certhold.conf",
	}
	for _, name := range expectedNames {
		if _, ok := entries[name]; !ok {
			t.Errorf("missing entry %q", name)
		}
	}

	certBytes := entries["etc/ssh/peer_ed25519-cert.pub"]
	pk, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		t.Fatalf("parsed key is not *ssh.Certificate: %T", pk)
	}
	if cert.KeyId != "vm1" {
		t.Errorf("KeyId = %q, want vm1", cert.KeyId)
	}
	wantPrincipals := []string{"vm1", "infra", "databases"}
	if !reflect.DeepEqual(cert.ValidPrincipals, wantPrincipals) {
		t.Errorf("ValidPrincipals = %v, want %v", cert.ValidPrincipals, wantPrincipals)
	}

	caPub, _, _, _, err := ssh.ParseAuthorizedKey(env.ca.PublicKeyAuthorizedKey())
	if err != nil {
		t.Fatalf("parse CA pub: %v", err)
	}
	if !bytes.Equal(cert.SignatureKey.Marshal(), caPub.Marshal()) {
		t.Error("cert.SignatureKey does not match CA public key")
	}

	caKnownHosts := string(entries["etc/ssh/ca_known_hosts"])
	if !bytes.HasPrefix([]byte(caKnownHosts), []byte("@cert-authority certhold.test ")) {
		t.Errorf("ca_known_hosts unexpected prefix: %q", caKnownHosts)
	}

	authPrincipals := string(entries["etc/ssh/auth_principals/root"])
	if want := "manager\ninfra\ndatabases\n"; authPrincipals != want {
		t.Errorf("auth_principals/root = %q, want %q", authPrincipals, want)
	}

	peer, err := env.db.GetPeer(ctx, "vm1")
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if peer.Serial != cert.Serial {
		t.Errorf("peer.Serial = %d, want %d", peer.Serial, cert.Serial)
	}

	gs, err := env.db.GetPeerGroups(ctx, "vm1")
	if err != nil {
		t.Fatalf("GetPeerGroups: %v", err)
	}
	if !reflect.DeepEqual(gs, []string{"databases", "infra"}) {
		t.Errorf("peer groups = %v, want [databases infra]", gs)
	}

	as, err := env.db.GetPeerAllowedGroups(ctx, "vm1")
	if err != nil {
		t.Fatalf("GetPeerAllowedGroups: %v", err)
	}
	if !reflect.DeepEqual(as, []string{"databases", "infra"}) {
		t.Errorf("peer allowed groups = %v, want [databases infra]", as)
	}
}

func TestEnrollTokenAlreadyConsumed(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	const tok = "tok-consume-twice"
	if err := env.db.InsertToken(ctx, tok, "vm2", "infra"); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}

	resp1, err := http.Get(env.srv.URL + "/enroll/" + tok)
	if err != nil {
		t.Fatalf("first GET: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp1.Body)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first status = %d, want 200", resp1.StatusCode)
	}

	resp2, err := http.Get(env.srv.URL + "/enroll/" + tok)
	if err != nil {
		t.Fatalf("second GET: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusGone {
		body, _ := io.ReadAll(resp2.Body)
		t.Errorf("second status = %d, want 410; body=%s", resp2.StatusCode, body)
	}
	if ct := resp2.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var payload map[string]string
	if err := json.NewDecoder(resp2.Body).Decode(&payload); err != nil {
		t.Errorf("decode JSON error body: %v", err)
	}
	if payload["error"] == "" {
		t.Errorf("error field missing: %v", payload)
	}
}

func TestEnrollUnknownToken(t *testing.T) {
	env := setupTestEnv(t)

	resp, err := http.Get(env.srv.URL + "/enroll/does-not-exist")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d, want 404; body=%s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var payload map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Errorf("decode JSON error body: %v", err)
	}
	if payload["error"] == "" {
		t.Errorf("error field missing: %v", payload)
	}
}

func TestEnrollMethodNotAllowed(t *testing.T) {
	env := setupTestEnv(t)
	req, err := http.NewRequest(http.MethodPost, env.srv.URL+"/enroll/whatever", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Errorf("POST status = %d, want non-2xx", resp.StatusCode)
	}
}
