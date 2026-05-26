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
)

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

	database, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	mux := httpserver.New(database)

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
