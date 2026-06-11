package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestHealthz(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	for _, v := range []int{1, 2} {
		if err := env.db.InsertCAVersion(ctx, v); err != nil {
			t.Fatalf("InsertCAVersion %d: %v", v, err)
		}
	}
	if err := env.db.SetActiveCAVersion(ctx, 2); err != nil {
		t.Fatalf("SetActiveCAVersion: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := env.db.BumpFleetRev(ctx); err != nil {
			t.Fatalf("BumpFleetRev: %v", err)
		}
	}

	resp, body := fetchBody(t, env.srv.URL+"/healthz")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	var got healthzResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode body %q: %v", body, err)
	}
	if got.FleetRev != 3 || got.CAVersion != 2 {
		t.Errorf("body = %+v, want fleet_rev=3 ca_version=2", got)
	}
	for _, secret := range []string{"token", "key", "cert"} {
		if strings.Contains(strings.ToLower(string(body)), secret) {
			t.Errorf("healthz body mentions %q: %s", secret, body)
		}
	}
}

func TestHealthzFreshDB(t *testing.T) {
	env := setupTestEnv(t)
	resp, body := fetchBody(t, env.srv.URL+"/healthz")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	var got healthzResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode body %q: %v", body, err)
	}
	if got.FleetRev != 0 || got.CAVersion != 0 {
		t.Errorf("body = %+v, want zeros on a fresh db", got)
	}
}

func TestHealthzDBError(t *testing.T) {
	env := setupTestEnv(t)
	if err := env.db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	resp, body := fetchBody(t, env.srv.URL+"/healthz")
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	assertJSONErr(t, body, "fleet rev")
}
