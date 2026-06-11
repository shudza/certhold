package tui

import (
	"context"
	"net"
	"testing"
)

func TestTCPProbeSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	latency, err := tcpProbe(context.Background(), host, port)
	if err != nil {
		t.Fatalf("probe of a live listener: %v", err)
	}
	if latency <= 0 {
		t.Fatalf("latency = %v, want > 0", latency)
	}
}

func TestTCPProbeRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	ln.Close()
	if _, err := tcpProbe(context.Background(), host, port); err == nil {
		t.Fatal("probe of a closed port must error")
	}
}
