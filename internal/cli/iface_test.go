package cli

import (
	"bytes"
	"net"
	"strings"
	"testing"
)

func withListInterfaces(t *testing.T, cands []ifaceCandidate, err error) {
	t.Helper()
	orig := listInterfaces
	listInterfaces = func() ([]ifaceCandidate, error) { return cands, err }
	t.Cleanup(func() { listInterfaces = orig })
}

func TestSelectInterface_ListenIPSynthetic(t *testing.T) {
	withListInterfaces(t, nil, nil)
	var buf bytes.Buffer
	c, err := selectInterface("10.0.0.5", false, strings.NewReader(""), &buf)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !c.IP.Equal(net.ParseIP("10.0.0.5").To4()) {
		t.Errorf("got %v want 10.0.0.5", c.IP)
	}
}

func TestSelectInterface_ListenIPInvalid(t *testing.T) {
	var buf bytes.Buffer
	if _, err := selectInterface("not-an-ip", false, strings.NewReader(""), &buf); err == nil {
		t.Fatal("expected error")
	}
}

func TestSelectInterface_ListenIPNotIPv4(t *testing.T) {
	var buf bytes.Buffer
	if _, err := selectInterface("::1", false, strings.NewReader(""), &buf); err == nil {
		t.Fatal("expected error for IPv6")
	}
}

func TestSelectInterface_SingleAutoSelect(t *testing.T) {
	withListInterfaces(t, []ifaceCandidate{{Name: "eth0", IP: net.ParseIP("192.168.1.10").To4()}}, nil)
	var buf bytes.Buffer
	c, err := selectInterface("", false, strings.NewReader(""), &buf)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if c.Name != "eth0" {
		t.Errorf("got %q", c.Name)
	}
}

func TestSelectInterface_ZeroCandidates(t *testing.T) {
	withListInterfaces(t, nil, nil)
	var buf bytes.Buffer
	if _, err := selectInterface("", false, strings.NewReader(""), &buf); err == nil {
		t.Fatal("expected error")
	}
}

func TestSelectInterface_NoPromptMultipleErrors(t *testing.T) {
	withListInterfaces(t, []ifaceCandidate{
		{Name: "eth0", IP: net.ParseIP("192.168.1.10").To4()},
		{Name: "wlan0", IP: net.ParseIP("10.0.0.7").To4()},
	}, nil)
	var buf bytes.Buffer
	_, err := selectInterface("", true, strings.NewReader(""), &buf)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "192.168.1.10") || !strings.Contains(err.Error(), "10.0.0.7") {
		t.Errorf("error missing IPs: %v", err)
	}
}

func TestSelectInterface_PromptPicksSecond(t *testing.T) {
	withListInterfaces(t, []ifaceCandidate{
		{Name: "eth0", IP: net.ParseIP("192.168.1.10").To4()},
		{Name: "wlan0", IP: net.ParseIP("10.0.0.7").To4()},
	}, nil)
	var buf bytes.Buffer
	c, err := selectInterface("", false, strings.NewReader("2\n"), &buf)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if c.Name != "wlan0" {
		t.Errorf("got %q want wlan0", c.Name)
	}
	if !strings.Contains(buf.String(), "Detected network interfaces:") {
		t.Errorf("prompt missing in output: %q", buf.String())
	}
}

func TestSelectInterface_BadInputExhaustsAttempts(t *testing.T) {
	withListInterfaces(t, []ifaceCandidate{
		{Name: "eth0", IP: net.ParseIP("192.168.1.10").To4()},
		{Name: "wlan0", IP: net.ParseIP("10.0.0.7").To4()},
	}, nil)
	var buf bytes.Buffer
	_, err := selectInterface("", false, strings.NewReader("abc\n\n4\n"), &buf)
	if err == nil {
		t.Fatal("expected error after 3 bad attempts")
	}
}

func TestSelectInterface_EOFAborts(t *testing.T) {
	withListInterfaces(t, []ifaceCandidate{
		{Name: "eth0", IP: net.ParseIP("192.168.1.10").To4()},
		{Name: "wlan0", IP: net.ParseIP("10.0.0.7").To4()},
	}, nil)
	var buf bytes.Buffer
	_, err := selectInterface("", false, strings.NewReader(""), &buf)
	if err == nil || !strings.Contains(err.Error(), "init aborted") {
		t.Fatalf("expected init aborted, got %v", err)
	}
}

func TestSelectInterface_QAborts(t *testing.T) {
	withListInterfaces(t, []ifaceCandidate{
		{Name: "eth0", IP: net.ParseIP("192.168.1.10").To4()},
		{Name: "wlan0", IP: net.ParseIP("10.0.0.7").To4()},
	}, nil)
	var buf bytes.Buffer
	_, err := selectInterface("", false, strings.NewReader("q\n"), &buf)
	if err == nil || !strings.Contains(err.Error(), "init aborted") {
		t.Fatalf("expected init aborted, got %v", err)
	}
}
