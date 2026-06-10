package peerfiles

import (
	"bytes"
	"strings"
	"testing"
)

func sampleRefreshBundle() RefreshBundle {
	return RefreshBundle{
		InstanceKey: testInstanceKey,
		PeerName:    "web1",
		CLIVersion:  "1.2.3",
		CertPub:     []byte("CERT"),
		CLIScript:   []byte("#!/bin/sh\necho cli\n"),
		Hosts:       []HostEntry{{Name: "db1", Address: "10.0.0.2", User: "deploy"}},
		FleetRev:    42,
		CertSerial:  7,
	}
}

func TestBuildRefreshBundle_Entries(t *testing.T) {
	in := sampleRefreshBundle()
	data, err := BuildRefreshBundle(in)
	if err != nil {
		t.Fatalf("BuildRefreshBundle: %v", err)
	}
	got := extractUser(t, data)
	want := map[string]int64{
		"id_ed25519_" + in.InstanceKey + "-cert.pub": 0644,
		"config":       0644,
		"certhold-cli": 0755,
		"manifest":     0644,
	}
	if len(got) != len(want) {
		t.Fatalf("entry count: got %d want %d: %v", len(got), len(want), keys(got))
	}
	for name, mode := range want {
		e, ok := got[name]
		if !ok {
			t.Errorf("missing %q; have %v", name, keys(got))
			continue
		}
		if e.mode != mode {
			t.Errorf("%s mode: got %o want %o", name, e.mode, mode)
		}
	}
	if !bytes.Equal(got["id_ed25519_"+in.InstanceKey+"-cert.pub"].data, in.CertPub) {
		t.Errorf("cert entry = %q want %q", got["id_ed25519_"+in.InstanceKey+"-cert.pub"].data, in.CertPub)
	}
	if !bytes.Equal(got["certhold-cli"].data, in.CLIScript) {
		t.Errorf("certhold-cli entry = %q want %q", got["certhold-cli"].data, in.CLIScript)
	}
	if cfg := string(got["config"].data); cfg != V2SshClientBlockWithHosts(in.InstanceKey, in.Hosts) {
		t.Errorf("config entry = %q\nwant %q", cfg, V2SshClientBlockWithHosts(in.InstanceKey, in.Hosts))
	}
}

func TestBuildRefreshBundle_Manifest(t *testing.T) {
	in := sampleRefreshBundle()
	data, err := BuildRefreshBundle(in)
	if err != nil {
		t.Fatalf("BuildRefreshBundle: %v", err)
	}
	got := extractUser(t, data)
	manifest := string(got["manifest"].data)
	want := "PEER_NAME=web1\n" +
		"INSTANCE_KEY=" + in.InstanceKey + "\n" +
		"FLEET_REV=42\n" +
		"CERT_SERIAL=7\n" +
		"CLI_VERSION=1.2.3\n"
	if manifest != want {
		t.Errorf("manifest = %q\nwant %q", manifest, want)
	}
	if strings.Contains(manifest, "\r") {
		t.Errorf("manifest must be LF-terminated only: %q", manifest)
	}
}

func TestBuildRefreshBundle_NoPrivateMaterial(t *testing.T) {
	in := sampleRefreshBundle()
	data, err := BuildRefreshBundle(in)
	if err != nil {
		t.Fatalf("BuildRefreshBundle: %v", err)
	}
	got := extractUser(t, data)
	if _, ok := got["id_ed25519_"+in.InstanceKey]; ok {
		t.Errorf("refresh bundle must not carry the private key; have %v", keys(got))
	}
	if _, ok := got["ca_authorized_keys"]; ok {
		t.Errorf("refresh bundle must not carry ca_authorized_keys; have %v", keys(got))
	}
}
