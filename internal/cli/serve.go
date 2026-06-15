package cli

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/httpserver"
	"github.com/shudza/certhold/internal/ops"
	"github.com/shudza/certhold/internal/sshpush"
)

// serveDial is overridden in tests.
var serveDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
	return sshpush.Dial(ctx, host, opts)
}

// servePeerPass supplies the manager peer-key passphrase to the unattended
// enroll-time probe from CERTHOLD_PEER_PASSPHRASE only — `serve` has no tty to
// prompt. A plaintext manager key never calls this; an encrypted key with the
// env var unset fails the capture dial, and the peer is simply recorded
// push-unreachable until a later interactive push/probe seeds it.
func servePeerPass() ([]byte, error) {
	if v, ok := os.LookupEnv(envPeerPassphrase); ok && v != "" {
		return []byte(v), nil
	}
	return nil, fmt.Errorf("manager peer key is passphrase-protected but %s is not set; cannot probe unattended", envPeerPassphrase)
}

func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the HTTPS enroll endpoint",
		RunE:  runServe,
	}
	cmd.Flags().String("addr", ":8443", "address to listen on")
	cmd.Flags().String("tls-cert", "", "path to TLS certificate (optional; if unset, a self-signed cert is generated)")
	cmd.Flags().String("tls-key", "", "path to TLS key (optional; if unset, a self-signed cert is generated)")
	return cmd
}

func runServe(cmd *cobra.Command, args []string) error {
	addr, err := cmd.Flags().GetString("addr")
	if err != nil {
		return err
	}
	tlsCert, err := cmd.Flags().GetString("tls-cert")
	if err != nil {
		return err
	}
	tlsKey, err := cmd.Flags().GetString("tls-key")
	if err != nil {
		return err
	}
	if (tlsCert == "") != (tlsKey == "") {
		return errors.New("--tls-cert and --tls-key must be provided together")
	}

	dbPath, err := cmd.Root().PersistentFlags().GetString("db")
	if err != nil {
		return fmt.Errorf("get db: %w", err)
	}
	dbPath = expandHome(dbPath)

	dataDir, err := cmd.Root().PersistentFlags().GetString("data-dir")
	if err != nil {
		return fmt.Errorf("get data-dir: %w", err)
	}
	dataDir = expandHome(dataDir)

	database, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	mux := httpserver.NewWithProbe(database, enrollReachabilityProbe(database, dataDir))

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	out := cmd.OutOrStdout()

	var (
		useExplicit  bool
		selfSignedFP string
	)
	if tlsCert != "" && tlsKey != "" {
		useExplicit = true
		fmt.Fprintf(out, "certhold serve listening (TLS) on https://%s\n", listener.Addr().String())
	} else {
		cert, der, err := generateSelfSigned(addr)
		if err != nil {
			_ = listener.Close()
			return fmt.Errorf("generate self-signed cert: %w", err)
		}
		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   defaultTLSMinVersion,
		}
		selfSignedFP = certFingerprint(der)
		fmt.Fprintf(out, "certhold serve listening (TLS, self-signed) on https://%s\n", listener.Addr().String())
		fmt.Fprintf(out, "cert SHA256: %s\n", selfSignedFP)
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		var serveErr error
		if useExplicit {
			serveErr = srv.ServeTLS(listener, tlsCert, tlsKey)
		} else {
			serveErr = srv.ServeTLS(listener, "", "")
		}
		errCh <- serveErr
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		<-errCh
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve: %w", err)
	}
}

// probeRetries / probeBackoff give the peer's sshd a brief grace period: at the
// install HTTP callback the peer is mid-install and sshd, while normally already
// up (the install does not touch it), can momentarily refuse the dial. A few
// short retries cover that window without making a truly unreachable
// (non-bidirectional) peer block for long. A peer the manager genuinely cannot
// reach simply ends marked push_reachable=0 and is routed to self-fetch.
var (
	probeRetries = 3
	probeBackoff = 2 * time.Second
)

// enrollReachabilityProbe returns the serve-side probe wired into the enroll
// handler: it dials the peer (capturing its host key into the manager's
// known_hosts) to confirm the manager can push to it, retrying briefly to let
// sshd come up, and records peers.push_reachable. It uses serve's --data-dir to
// locate the manager's own peer cert/key, and servePeerPass for the manager
// key's passphrase when encrypted (env-only, since serve is unattended). If the
// key is encrypted and CERTHOLD_PEER_PASSPHRASE is unset the dial fails and the
// peer is recorded unreachable until a manual push/probe seeds it. Errors are
// best-effort — this never aborts enrollment.
func enrollReachabilityProbe(database *db.DB, dataDir string) httpserver.ReachabilityProbe {
	return func(peerName, host, targetUser string) {
		deps := ops.Deps{DB: database, DataDir: dataDir, Dial: ops.DialFn(serveDial), PeerPass: servePeerPass}
		var (
			reachable bool
			lastErr   error
		)
		for attempt := 0; attempt < probeRetries; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			r, err := ops.ProbeAndCaptureHostKey(ctx, deps, peerName, host, targetUser)
			cancel()
			reachable, lastErr = r, err
			if err == nil || reachable {
				break
			}
			if attempt < probeRetries-1 {
				time.Sleep(probeBackoff)
			}
		}
		if reachable {
			fmt.Fprintf(os.Stderr, "enroll: captured host key for %q (%s); pushes enabled\n", peerName, host)
		} else {
			fmt.Fprintf(os.Stderr, "enroll: %q (%s) is not reachable for push (%v); routed to self-fetch (certhold-cli refresh)\n", peerName, host, lastErr)
		}
	}
}
