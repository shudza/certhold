package peerfiles

import (
	"strings"
	"testing"
)

func TestValidateDialAddressAccepts(t *testing.T) {
	for _, addr := range []string{
		"",
		"10.0.0.5",
		"host.example.com",
		"host:2222",
		"::1",
		"[::1]:22",
		"fe80::1%eth0",
		strings.Repeat("a", 255),
	} {
		if err := ValidateDialAddress(addr); err != nil {
			t.Errorf("ValidateDialAddress(%q) = %v, want nil", addr, err)
		}
	}
}

func TestValidateDialAddressRejects(t *testing.T) {
	for _, tc := range []struct {
		name, addr string
	}{
		{"space", "10.0.0.5 prod"},
		{"newline injection", "a\nProxyCommand evil"},
		{"tab", "host\t22"},
		{"carriage return", "host\rname"},
		{"control char", "host\x01name"},
		{"del", "host\x7fname"},
		{"non-ascii", "höst.example.com"},
		{"double quote", `ho"st`},
		{"unbalanced single quote", "10.0.0.5'"},
		{"balanced single quotes", "'10.0.0.5'"},
		{"too long", strings.Repeat("a", 300)},
	} {
		if err := ValidateDialAddress(tc.addr); err == nil {
			t.Errorf("%s: ValidateDialAddress(%q) = nil, want error", tc.name, tc.addr)
		}
	}
}
