package tui

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shudza/certhold/internal/db"
	"golang.org/x/crypto/ssh"
)

func certBlob(t *testing.T, validAfter, validBefore uint64) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	cert := &ssh.Certificate{
		Key:         sshPub,
		Serial:      11,
		CertType:    ssh.UserCert,
		KeyId:       "test",
		ValidAfter:  validAfter,
		ValidBefore: validBefore,
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	return cert.Marshal()
}

func seedTuiDB(t *testing.T) (string, time.Time) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tui.sqlite")
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "base_url"), []byte("https://mgr.example:8443\n"), 0644); err != nil {
		t.Fatalf("write base_url: %v", err)
	}
	d, err := db.Open(path)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	ctx := t.Context()

	if err := d.InsertCAVersion(ctx, 1); err != nil {
		t.Fatalf("InsertCAVersion: %v", err)
	}
	if err := d.SetActiveCAVersion(ctx, 1); err != nil {
		t.Fatalf("SetActiveCAVersion: %v", err)
	}
	if err := d.BumpFleetRev(ctx); err != nil {
		t.Fatalf("BumpFleetRev: %v", err)
	}

	until := time.Now().Add(48 * time.Hour).Truncate(time.Second).UTC()
	if err := d.InsertPeer(ctx, "alpha", 11, "SHA256:fp-alpha", []byte("ka"), "alice", true, "tok-secret-alpha"); err != nil {
		t.Fatalf("InsertPeer alpha: %v", err)
	}
	if err := d.SetPeerAddress(ctx, "alpha", "10.0.0.5"); err != nil {
		t.Fatalf("SetPeerAddress: %v", err)
	}
	if err := d.SetPeerCert(ctx, "alpha", certBlob(t, uint64(time.Now().Unix()), uint64(until.Unix())), 11); err != nil {
		t.Fatalf("SetPeerCert alpha: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "alpha", []string{"infra", "db"}); err != nil {
		t.Fatalf("SetPeerGroups alpha: %v", err)
	}
	if err := d.SetPeerAllowedGroups(ctx, "alpha", []string{"ops"}); err != nil {
		t.Fatalf("SetPeerAllowedGroups alpha: %v", err)
	}

	if err := d.InsertPeer(ctx, "beta", 12, "SHA256:fp-beta", []byte("kb"), "", true, ""); err != nil {
		t.Fatalf("InsertPeer beta: %v", err)
	}
	if err := d.SetPeerGroups(ctx, "beta", []string{"infra"}); err != nil {
		t.Fatalf("SetPeerGroups beta: %v", err)
	}
	if err := d.SetPeerRevoked(ctx, "beta"); err != nil {
		t.Fatalf("SetPeerRevoked beta: %v", err)
	}

	if err := d.InsertPeer(ctx, "gamma", 13, "SHA256:fp-gamma", []byte("kg"), "bob", false, "tok-secret-gamma"); err != nil {
		t.Fatalf("InsertPeer gamma: %v", err)
	}
	if err := d.SetPeerCert(ctx, "gamma", certBlob(t, 0, ssh.CertTimeInfinity), 13); err != nil {
		t.Fatalf("SetPeerCert gamma: %v", err)
	}

	return path, until
}

func TestLoad(t *testing.T) {
	path, until := seedTuiDB(t)
	d, err := db.Open(path)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	ctx := t.Context()

	fd, err := load(ctx, d, path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if fd.DBPath != path {
		t.Errorf("DBPath = %q, want %q", fd.DBPath, path)
	}
	if fd.BaseURL != "https://mgr.example:8443" {
		t.Errorf("BaseURL = %q, want the trimmed base_url file", fd.BaseURL)
	}
	if fd.FleetRev < 1 {
		t.Errorf("FleetRev = %d, want >= 1", fd.FleetRev)
	}
	if !fd.CAVersionKnown || fd.CAVersion != 1 {
		t.Errorf("CA version = (%d, %v), want (1, true)", fd.CAVersion, fd.CAVersionKnown)
	}
	if len(fd.Peers) != 3 {
		t.Fatalf("peers = %d, want 3", len(fd.Peers))
	}

	alpha, beta, gamma := fd.Peers[0], fd.Peers[1], fd.Peers[2]
	if alpha.Name != "alpha" || beta.Name != "beta" || gamma.Name != "gamma" {
		t.Fatalf("peers not sorted by name: %s %s %s", alpha.Name, beta.Name, gamma.Name)
	}
	if alpha.DialHost != "10.0.0.5" {
		t.Errorf("alpha DialHost = %q, want recorded address", alpha.DialHost)
	}
	if beta.DialHost != "beta" {
		t.Errorf("beta DialHost = %q, want name fallback", beta.DialHost)
	}
	if !alpha.HasPullToken || beta.HasPullToken {
		t.Errorf("HasPullToken alpha=%v beta=%v, want true/false", alpha.HasPullToken, beta.HasPullToken)
	}
	if alpha.Expires.state != certAt || !alpha.Expires.until.Equal(until) {
		t.Errorf("alpha expiry = %+v, want certAt %s", alpha.Expires, until)
	}
	if beta.Expires.state != certNone {
		t.Errorf("beta expiry = %+v, want certNone", beta.Expires)
	}
	if !beta.Revoked {
		t.Error("beta should be revoked")
	}
	if gamma.Expires.state != certForever {
		t.Errorf("gamma expiry = %+v, want certForever", gamma.Expires)
	}
	if gamma.Inbound {
		t.Error("gamma should be a client-style peer (no inbound)")
	}
	if len(alpha.Groups) != 2 || len(alpha.Allowed) != 1 {
		t.Errorf("alpha groups/allowed = %v/%v", alpha.Groups, alpha.Allowed)
	}

	byName := map[string]groupRow{}
	for _, g := range fd.Groups {
		byName[g.Name] = g
	}
	infra, ok := byName["infra"]
	if !ok || infra.PeerCount != 2 || len(infra.Members) != 2 {
		t.Errorf("infra group = %+v, want 2 members", infra)
	}
	ops, ok := byName["ops"]
	if !ok || len(ops.AllowedBy) != 1 || ops.AllowedBy[0] != "alpha" {
		t.Errorf("ops group = %+v, want allowed-by [alpha]", ops)
	}
}

func TestReadBaseURLMissing(t *testing.T) {
	if got := readBaseURL(filepath.Join(t.TempDir(), "state.db")); got != "" {
		t.Errorf("readBaseURL with no file = %q, want empty", got)
	}
}

func TestParseCertExpiry(t *testing.T) {
	if got := parseCertExpiry(nil); got.state != certNone {
		t.Errorf("nil blob = %+v, want certNone", got)
	}
	if got := parseCertExpiry([]byte("not a cert")); got.state != certNone {
		t.Errorf("garbage blob = %+v, want certNone", got)
	}
	until := time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC)
	got := parseCertExpiry(certBlob(t, uint64(until.Add(-time.Hour).Unix()), uint64(until.Unix())))
	if got.state != certAt || !got.until.Equal(until) {
		t.Errorf("dated cert = %+v, want certAt %s", got, until)
	}
	if got := parseCertExpiry(certBlob(t, 0, ssh.CertTimeInfinity)); got.state != certForever {
		t.Errorf("infinity cert = %+v, want certForever", got)
	}
}

func TestPullTokenNeverRendered(t *testing.T) {
	path, _ := seedTuiDB(t)
	d, err := db.Open(path)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer d.Close()
	fd, err := load(t.Context(), d, path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	m := NewModel(context.Background(), fd, nil)

	views := []string{m.View()}
	views = append(views, press(t, m, "enter").View())
	views = append(views, press(t, m, "j", "j", "enter").View())
	views = append(views, press(t, m, "2").View())
	views = append(views, press(t, m, "3").View())
	views = append(views, press(t, m, "/", "t", "o", "k").View())
	for i, v := range views {
		if strings.Contains(v, "tok-secret") {
			t.Fatalf("view %d leaks a pull token:\n%s", i, v)
		}
	}
}
