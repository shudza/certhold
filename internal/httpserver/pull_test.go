package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/shudza/certhold/internal/clientcli"
)

func (e *testEnv) seedPullPeer(t *testing.T, name, pullToken string, serial uint64, cert []byte) {
	t.Helper()
	ctx := context.Background()
	if err := e.db.InsertPeer(ctx, name, serial, "fp-"+name, []byte("authk-"+name), "", false, pullToken); err != nil {
		t.Fatalf("InsertPeer: %v", err)
	}
	if cert != nil {
		if err := e.db.SetPeerCert(ctx, name, cert, serial); err != nil {
			t.Fatalf("SetPeerCert: %v", err)
		}
	}
}

func (e *testEnv) seedReachableHost(t *testing.T, client, host, targetUser, address, group string) {
	t.Helper()
	ctx := context.Background()
	if err := e.db.InsertPeer(ctx, host, 2, "fp-"+host, []byte("authk-"+host), targetUser, true, ""); err != nil {
		t.Fatalf("InsertPeer %s: %v", host, err)
	}
	if err := e.db.SetPeerAddress(ctx, host, address); err != nil {
		t.Fatalf("SetPeerAddress: %v", err)
	}
	if err := e.db.CreateGroup(ctx, group); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := e.db.SetPeerGroups(ctx, client, []string{group}); err != nil {
		t.Fatalf("SetPeerGroups: %v", err)
	}
	if err := e.db.SetPeerAllowedGroups(ctx, host, []string{group}); err != nil {
		t.Fatalf("SetPeerAllowedGroups: %v", err)
	}
}

func fetchBody(t *testing.T, url string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, body
}

func assertJSONErr(t *testing.T, body []byte, wantSubstr string) {
	t.Helper()
	var payload map[string]string
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode error body %q: %v", body, err)
	}
	if !strings.Contains(payload["error"], wantSubstr) {
		t.Errorf("error = %q, want substring %q", payload["error"], wantSubstr)
	}
}

func TestPullBundle(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	certPub := []byte("ssh-ed25519-cert-v01@openssh.com AAAAfake client\n")
	env.seedPullPeer(t, "laptop", "ptok-laptop", 7, certPub)
	env.seedReachableHost(t, "laptop", "server1", "deploy", "10.0.0.5", "prod")
	if err := env.db.BumpFleetRev(ctx); err != nil {
		t.Fatalf("BumpFleetRev: %v", err)
	}
	if err := env.db.BumpFleetRev(ctx); err != nil {
		t.Fatalf("BumpFleetRev: %v", err)
	}

	resp, body := fetchBody(t, env.srv.URL+"/pull/ptok-laptop")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/gzip" {
		t.Errorf("Content-Type = %q, want application/gzip", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}

	files := extractTarball(t, body)
	wantNames := []string{"id_ed25519_" + testInstanceKey + "-cert.pub", "config", "certhold-cli", "manifest"}
	if len(files) != len(wantNames) {
		t.Errorf("bundle has %d entries, want %d: %v", len(files), len(wantNames), files)
	}
	for _, name := range wantNames {
		if _, ok := files[name]; !ok {
			t.Errorf("bundle missing %q", name)
		}
	}
	if got := files["id_ed25519_"+testInstanceKey+"-cert.pub"]; !bytes.Equal(got, certPub) {
		t.Errorf("cert in bundle = %q, want %q", got, certPub)
	}
	if !bytes.Equal(files["certhold-cli"], clientcli.Script) {
		t.Errorf("certhold-cli in bundle differs from clientcli.Script")
	}

	rev, err := env.db.FleetRev(ctx)
	if err != nil {
		t.Fatalf("FleetRev: %v", err)
	}
	manifest := string(files["manifest"])
	for _, want := range []string{
		fmt.Sprintf("FLEET_REV=%d\n", rev),
		"PEER_NAME=laptop\n",
		"INSTANCE_KEY=" + testInstanceKey + "\n",
		"CERT_SERIAL=7\n",
		"CLI_VERSION=" + clientcli.Version + "\n",
	} {
		if !strings.Contains(manifest, want) {
			t.Errorf("manifest missing %q; manifest=%q", want, manifest)
		}
	}

	cfg := string(files["config"])
	wantStanza := "Host server1\n    HostName 10.0.0.5\n    User deploy\n"
	if !strings.Contains(cfg, wantStanza) {
		t.Errorf("config missing host stanza %q; config=%q", wantStanza, cfg)
	}
	if !strings.Contains(cfg, "# BEGIN certhold "+testInstanceKey) {
		t.Errorf("config missing keyed sentinel; config=%q", cfg)
	}
}

func TestPullTwiceByteIdentical(t *testing.T) {
	env := setupTestEnv(t)
	env.seedPullPeer(t, "laptop", "ptok", 1, []byte("cert-bytes\n"))

	resp1, body1 := fetchBody(t, env.srv.URL+"/pull/ptok")
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first pull status = %d, want 200", resp1.StatusCode)
	}
	resp2, body2 := fetchBody(t, env.srv.URL+"/pull/ptok")
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("second pull status = %d, want 200", resp2.StatusCode)
	}
	if !bytes.Equal(body1, body2) {
		t.Errorf("repeated pulls differ: %d vs %d bytes", len(body1), len(body2))
	}
}

func TestPullUnknownToken(t *testing.T) {
	env := setupTestEnv(t)
	resp, body := fetchBody(t, env.srv.URL+"/pull/does-not-exist")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	assertJSONErr(t, body, "token not found")

	resp, body = fetchBody(t, env.srv.URL+"/pull/does-not-exist/rev")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("rev status = %d, want 404", resp.StatusCode)
	}
	assertJSONErr(t, body, "token not found")
}

func TestPullEmptyTokenPath(t *testing.T) {
	env := setupTestEnv(t)
	for _, path := range []string{"/pull/", "/pull", "/pull//rev"} {
		resp, _ := fetchBody(t, env.srv.URL+path)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want 404", path, resp.StatusCode)
		}
	}
}

func TestPullRevokedPeer(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	env.seedPullPeer(t, "laptop", "ptok", 1, []byte("cert-bytes\n"))
	if err := env.db.SetPeerRevoked(ctx, "laptop"); err != nil {
		t.Fatalf("SetPeerRevoked: %v", err)
	}

	resp, body := fetchBody(t, env.srv.URL+"/pull/ptok")
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("status = %d, want 410", resp.StatusCode)
	}
	assertJSONErr(t, body, "revoked")

	resp, body = fetchBody(t, env.srv.URL+"/pull/ptok/rev")
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("rev status = %d, want 410", resp.StatusCode)
	}
	assertJSONErr(t, body, "revoked")
}

func TestPullNilCert(t *testing.T) {
	env := setupTestEnv(t)
	env.seedPullPeer(t, "laptop", "ptok", 1, nil)

	resp, body := fetchBody(t, env.srv.URL+"/pull/ptok")
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", resp.StatusCode)
	}
	assertJSONErr(t, body, "bundle unavailable")
}

func TestPullRevEndpoint(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	env.seedPullPeer(t, "laptop", "ptok", 1, []byte("cert-bytes\n"))

	resp, body := fetchBody(t, env.srv.URL+"/pull/ptok/rev")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	if string(body) != "0\n" {
		t.Errorf("body = %q, want %q", body, "0\n")
	}

	if err := env.db.BumpFleetRev(ctx); err != nil {
		t.Fatalf("BumpFleetRev: %v", err)
	}
	resp, body = fetchBody(t, env.srv.URL+"/pull/ptok/rev")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status after bump = %d, want 200", resp.StatusCode)
	}
	if string(body) != "1\n" {
		t.Errorf("body after bump = %q, want %q", body, "1\n")
	}
}
