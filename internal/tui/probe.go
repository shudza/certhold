package tui

import (
	"context"
	"net"
	"time"
)

const probeTimeout = 1500 * time.Millisecond

type ProbeFn func(ctx context.Context, host string) (time.Duration, error)

func defaultProbe(ctx context.Context, host string) (time.Duration, error) {
	return tcpProbe(ctx, host, "22")
}

func tcpProbe(ctx context.Context, host, port string) (time.Duration, error) {
	d := net.Dialer{Timeout: probeTimeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return 0, err
	}
	conn.Close()
	return time.Since(start), nil
}
