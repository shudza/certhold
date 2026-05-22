package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/sshpush"
)

var rekeyDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
	return sshpush.Dial(ctx, host, opts)
}

func newRekeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rekey",
		Short: "Rotate the CA: reissue certs for all peers, push atomically, retire old CA",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			hostname, err := cmd.Flags().GetString("hostname")
			if err != nil {
				return fmt.Errorf("get hostname: %w", err)
			}
			if hostname == "" {
				h, herr := os.Hostname()
				if herr != nil {
					return fmt.Errorf("hostname: %w", herr)
				}
				hostname = h
			}
			return runRekey(cmd, hostname)
		},
	}
	cmd.Flags().String("hostname", "", "certhold's own peer name (default: os.Hostname())")
	return cmd
}

func runRekey(cmd *cobra.Command, hostname string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	dataDir, err := cmd.Root().PersistentFlags().GetString("data-dir")
	if err != nil {
		return fmt.Errorf("get data-dir: %w", err)
	}
	dbPath, err := cmd.Root().PersistentFlags().GetString("db")
	if err != nil {
		return fmt.Errorf("get db: %w", err)
	}
	dataDir = expandHome(dataDir)
	dbPath = expandHome(dbPath)

	caDir := filepath.Join(dataDir, "ca")
	if _, err := ca.Load(caDir); err != nil {
		return fmt.Errorf("load ca: %w", err)
	}

	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	if _, err := d.GetPeer(ctx, hostname); err != nil {
		if errors.Is(err, db.ErrPeerNotFound) {
			return fmt.Errorf("certhold's own peer %q not found in db", hostname)
		}
		return fmt.Errorf("get self peer: %w", err)
	}

	peers, err := d.ListPeers(ctx)
	if err != nil {
		return fmt.Errorf("list peers: %w", err)
	}

	var others []db.Peer
	var self *db.Peer
	for i := range peers {
		p := peers[i]
		if p.Revoked {
			continue
		}
		if p.Name == hostname {
			self = &p
			continue
		}
		others = append(others, p)
	}
	if self == nil {
		return fmt.Errorf("certhold's own peer %q is revoked or missing", hostname)
	}

	nextCADir := filepath.Join(dataDir, "ca.next")
	if _, err := os.Stat(nextCADir); err == nil {
		return fmt.Errorf("ca.next already exists at %s; resolve manually before retrying", nextCADir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", nextCADir, err)
	}
	newCA, err := ca.Generate(nextCADir)
	if err != nil {
		return fmt.Errorf("generate new ca: %w", err)
	}
	newCAPub := newCA.PublicKeyAuthorizedKey()

	selfSSHDir := filepath.Join(dataDir, "self", "etc", "ssh")
	pushOpts := sshpush.Options{
		CertPath:       filepath.Join(selfSSHDir, "peer_ed25519-cert.pub"),
		KeyPath:        filepath.Join(selfSSHDir, "peer_ed25519"),
		KnownHostsPath: filepath.Join(selfSSHDir, "ca_known_hosts"),
		User:           "root",
	}

	out := cmd.OutOrStdout()
	errOut := cmd.ErrOrStderr()
	var updated []string

	for _, p := range others {
		groups, err := d.GetPeerGroups(ctx, p.Name)
		if err != nil {
			return abortRekey(errOut, fmt.Errorf("get groups for %s: %w", p.Name, err), updated)
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey(p.AuthorizedKey)
		if err != nil {
			return abortRekey(errOut, fmt.Errorf("parse pubkey for %s: %w", p.Name, err), updated)
		}
		principals := append([]string{p.Name}, groups...)
		certBytes, serial, err := newCA.SignCert(ca.SignOptions{
			Pubkey:     pk,
			KeyID:      p.Name,
			Principals: principals,
		})
		if err != nil {
			return abortRekey(errOut, fmt.Errorf("sign cert for %s: %w", p.Name, err), updated)
		}
		if err := pushRekey(ctx, p.Name, newCAPub, certBytes, pushOpts); err != nil {
			return abortRekey(errOut, fmt.Errorf("push %s: %w", p.Name, err), updated)
		}
		if err := d.UpdatePeerCertSerial(ctx, p.Name, serial); err != nil {
			return abortRekey(errOut, fmt.Errorf("update cert_serial %s: %w", p.Name, err), updated)
		}
		updated = append(updated, p.Name)
		fmt.Fprintf(out, "rekeyed %s (serial %d)\n", p.Name, serial)
	}

	selfGroups, err := d.GetPeerGroups(ctx, hostname)
	if err != nil {
		return abortRekey(errOut, fmt.Errorf("get groups for self: %w", err), updated)
	}
	selfPrincipals := []string{hostname, "manager"}
	for _, g := range selfGroups {
		if g != "manager" {
			selfPrincipals = append(selfPrincipals, g)
		}
	}
	selfPK, _, _, _, err := ssh.ParseAuthorizedKey(self.AuthorizedKey)
	if err != nil {
		return abortRekey(errOut, fmt.Errorf("parse self pubkey: %w", err), updated)
	}
	selfCertBytes, selfSerial, err := newCA.SignCert(ca.SignOptions{
		Pubkey:     selfPK,
		KeyID:      hostname,
		Principals: selfPrincipals,
	})
	if err != nil {
		return abortRekey(errOut, fmt.Errorf("sign self cert: %w", err), updated)
	}

	selfCAPath := filepath.Join(selfSSHDir, "ca.pub")
	selfCertPath := filepath.Join(selfSSHDir, "peer_ed25519-cert.pub")
	if err := writeFileAtomicLocal(selfCAPath, newCAPub, 0644); err != nil {
		return abortRekey(errOut, fmt.Errorf("write self ca.pub: %w", err), updated)
	}
	if err := writeFileAtomicLocal(selfCertPath, selfCertBytes, 0644); err != nil {
		return abortRekey(errOut, fmt.Errorf("write self cert: %w", err), updated)
	}
	if err := d.UpdatePeerCertSerial(ctx, hostname, selfSerial); err != nil {
		return abortRekey(errOut, fmt.Errorf("update self cert_serial: %w", err), updated)
	}
	updated = append(updated, hostname)
	fmt.Fprintf(out, "rekeyed %s (serial %d)\n", hostname, selfSerial)

	timestamp := time.Now().UTC().Format("20060102T150405")
	oldCADir := filepath.Join(dataDir, fmt.Sprintf("ca.old.%s", timestamp))
	if err := os.Rename(caDir, oldCADir); err != nil {
		return fmt.Errorf("rename old ca: %w", err)
	}
	if err := os.Rename(nextCADir, caDir); err != nil {
		_ = os.Rename(oldCADir, caDir)
		return fmt.Errorf("rename new ca: %w", err)
	}

	curVer, err := d.ActiveCAVersion(ctx)
	if err != nil && !errors.Is(err, db.ErrNoActiveCA) {
		return fmt.Errorf("active ca version: %w", err)
	}
	newVer := curVer + 1
	if err := d.InsertCAVersion(ctx, newVer); err != nil {
		return fmt.Errorf("insert ca version %d: %w", newVer, err)
	}
	if err := d.SetActiveCAVersion(ctx, newVer); err != nil {
		return fmt.Errorf("set active ca version %d: %w", newVer, err)
	}

	fmt.Fprintf(out, "Rekey complete: %d peers rotated, CA version %d active, old CA archived at %s\n", len(updated), newVer, oldCADir)
	return nil
}

func pushRekey(ctx context.Context, host string, caPub, certBytes []byte, opts sshpush.Options) error {
	if host == "" {
		return errors.New("empty host")
	}
	p, err := rekeyDial(ctx, host, opts)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer p.Close()
	if err := p.WriteFileAtomic(ctx, "/etc/ssh/ca.pub", caPub, fs.FileMode(0644)); err != nil {
		return fmt.Errorf("write ca.pub: %w", err)
	}
	if err := p.WriteFileAtomic(ctx, "/etc/ssh/peer_ed25519-cert.pub", certBytes, fs.FileMode(0644)); err != nil {
		return fmt.Errorf("write peer cert: %w", err)
	}
	if err := p.ReloadSSHD(ctx); err != nil {
		return fmt.Errorf("reload sshd: %w", err)
	}
	if err := p.VerifyHealth(ctx); err != nil {
		return fmt.Errorf("verify health: %w", err)
	}
	return nil
}

func abortRekey(errOut interface {
	Write(p []byte) (n int, err error)
}, cause error, updated []string) error {
	fmt.Fprintf(errOut, "rekey aborted: %v\n", cause)
	if len(updated) > 0 {
		fmt.Fprintf(errOut, "peers already rotated to new CA (recovery may be required): %v\n", updated)
	}
	return cause
}

func writeFileAtomicLocal(path string, content []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		cleanup()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("rename %s -> %s: %w", tmpName, path, err)
	}
	return nil
}
