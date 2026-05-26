package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/passphrase"
	"github.com/shudza/certhold/internal/sshpush"
)

type rekeyDeps struct {
	DataDir  string
	Hostname string
	DB       *db.DB
	Out      io.Writer
	Err      io.Writer
	// Dial is the SSH dialer used by the rekey loop. revoke (user-mode) and
	// rekey share this so test mocks can intercept either entry point through
	// the single package-level rekeyDial var.
	Dial func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error)
	// CAUnlock supplies the passphrase for the current (old) CA key; nil means
	// plaintext-only (erroring if an encrypted key is hit). PeerPassFn supplies
	// the manager peer key passphrase for pushes. RotatePassphrase, when true,
	// prompts for a fresh passphrase for the new CA key instead of reusing the
	// old one.
	CAUnlock         func() ([]byte, error)
	PeerPassFn       func() ([]byte, error)
	RotatePassphrase bool
}

// runRekeyCore generates a new CA, signs new certs for every non-revoked peer
// except those in `exclude`, pushes them, then atomically swaps CA directories
// and updates ca_versions. Used by `certhold rekey` and by `certhold revoke`
// on user-mode peers (where there is no native KRL).
func runRekeyCore(ctx context.Context, deps rekeyDeps, exclude map[string]bool) error {
	caDir := filepath.Join(deps.DataDir, "ca")
	if _, err := ca.LoadWithPassphrase(caDir, deps.CAUnlock); err != nil {
		return fmt.Errorf("load ca: %w", err)
	}

	self, err := deps.DB.GetPeer(ctx, deps.Hostname)
	if err != nil {
		if errors.Is(err, db.ErrPeerNotFound) {
			return fmt.Errorf("certhold's own peer %q not found in db", deps.Hostname)
		}
		return fmt.Errorf("get self peer: %w", err)
	}

	peers, err := deps.DB.ListPeers(ctx)
	if err != nil {
		return fmt.Errorf("list peers: %w", err)
	}
	var others []db.Peer
	for _, p := range peers {
		if p.Revoked || p.Name == deps.Hostname || exclude[p.Name] {
			continue
		}
		others = append(others, p)
	}

	nextCADir := filepath.Join(deps.DataDir, "ca.next")
	if _, err := os.Stat(nextCADir); err == nil {
		return fmt.Errorf("ca.next already exists at %s; resolve manually before retrying", nextCADir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", nextCADir, err)
	}

	newCAPass, err := newCAPassphrase(caDir, deps)
	if err != nil {
		return err
	}
	defer zeroBytes(newCAPass)
	newCA, err := ca.GenerateWithPassphrase(nextCADir, newCAPass)
	if err != nil {
		return fmt.Errorf("generate new ca: %w", err)
	}
	newCAPub := newCA.PublicKeyAuthorizedKey()

	pushOpts := selfPushOptions(deps.DataDir, self.Mode, deps.PeerPassFn)
	pushOpts.User = pushUser(self)

	var updated []string
	for _, p := range others {
		groups, err := deps.DB.GetPeerGroups(ctx, p.Name)
		if err != nil {
			return abortRekey(deps.Err, fmt.Errorf("get groups for %s: %w", p.Name, err), updated)
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey(p.AuthorizedKey)
		if err != nil {
			return abortRekey(deps.Err, fmt.Errorf("parse pubkey for %s: %w", p.Name, err), updated)
		}
		principals := append([]string{p.Name}, groups...)
		certBytes, serial, err := newCA.SignCert(ca.SignOptions{
			Pubkey:     pk,
			KeyID:      p.Name,
			Principals: principals,
		})
		if err != nil {
			return abortRekey(deps.Err, fmt.Errorf("sign cert for %s: %w", p.Name, err), updated)
		}

		peerForPush := p
		allowed, err := deps.DB.GetPeerAllowedGroups(ctx, p.Name)
		if err != nil {
			return abortRekey(deps.Err, fmt.Errorf("get allowed groups for %s: %w", p.Name, err), updated)
		}
		if err := pushPeerRekey(ctx, deps.Dial, &peerForPush, newCAPub, certBytes, allowed, pushOpts); err != nil {
			return abortRekey(deps.Err, fmt.Errorf("push %s: %w", p.Name, err), updated)
		}
		if err := deps.DB.UpdatePeerCertSerial(ctx, p.Name, serial); err != nil {
			return abortRekey(deps.Err, fmt.Errorf("update cert_serial %s: %w", p.Name, err), updated)
		}
		updated = append(updated, p.Name)
		fmt.Fprintf(deps.Out, "rekeyed %s (serial %d)\n", p.Name, serial)
	}

	selfGroups, err := deps.DB.GetPeerGroups(ctx, deps.Hostname)
	if err != nil {
		return abortRekey(deps.Err, fmt.Errorf("get groups for self: %w", err), updated)
	}
	selfPrincipals := []string{deps.Hostname, "manager"}
	for _, g := range selfGroups {
		if g != "manager" {
			selfPrincipals = append(selfPrincipals, g)
		}
	}
	selfPK, _, _, _, err := ssh.ParseAuthorizedKey(self.AuthorizedKey)
	if err != nil {
		return abortRekey(deps.Err, fmt.Errorf("parse self pubkey: %w", err), updated)
	}
	selfCertBytes, selfSerial, err := newCA.SignCert(ca.SignOptions{
		Pubkey:     selfPK,
		KeyID:      deps.Hostname,
		Principals: selfPrincipals,
	})
	if err != nil {
		return abortRekey(deps.Err, fmt.Errorf("sign self cert: %w", err), updated)
	}

	if err := writeSelfRekey(deps.DataDir, self, newCAPub, selfCertBytes); err != nil {
		return abortRekey(deps.Err, fmt.Errorf("update self files: %w", err), updated)
	}
	if err := deps.DB.UpdatePeerCertSerial(ctx, deps.Hostname, selfSerial); err != nil {
		return abortRekey(deps.Err, fmt.Errorf("update self cert_serial: %w", err), updated)
	}
	updated = append(updated, deps.Hostname)
	fmt.Fprintf(deps.Out, "rekeyed %s (serial %d)\n", deps.Hostname, selfSerial)

	timestamp := time.Now().UTC().Format("20060102T150405")
	oldCADir := filepath.Join(deps.DataDir, fmt.Sprintf("ca.old.%s", timestamp))
	if err := os.Rename(caDir, oldCADir); err != nil {
		return fmt.Errorf("rename old ca: %w", err)
	}
	if err := os.Rename(nextCADir, caDir); err != nil {
		_ = os.Rename(oldCADir, caDir)
		return fmt.Errorf("rename new ca: %w", err)
	}

	curVer, err := deps.DB.ActiveCAVersion(ctx)
	if err != nil && !errors.Is(err, db.ErrNoActiveCA) {
		return fmt.Errorf("active ca version: %w", err)
	}
	newVer := curVer + 1
	if err := deps.DB.InsertCAVersion(ctx, newVer); err != nil {
		return fmt.Errorf("insert ca version %d: %w", newVer, err)
	}
	if err := deps.DB.SetActiveCAVersion(ctx, newVer); err != nil {
		return fmt.Errorf("set active ca version %d: %w", newVer, err)
	}

	fmt.Fprintf(deps.Out, "Rekey complete: %d peers rotated, CA version %d active, old CA archived at %s\n", len(updated), newVer, oldCADir)
	return nil
}

// newCAPassphrase decides the passphrase for the freshly generated CA key.
// When --rotate-passphrase is set it prompts (with confirmation) for a fresh
// one. Otherwise it mirrors the old CA's protection: an encrypted old CA reuses
// the same (memoized) passphrase; a plaintext old CA yields a nil passphrase so
// the new key is also plaintext (no spurious prompt).
func newCAPassphrase(caDir string, deps rekeyDeps) ([]byte, error) {
	if deps.RotatePassphrase {
		pass, err := passphrase.PromptConfirm("New CA passphrase: ", "")
		if err != nil {
			return nil, fmt.Errorf("read new ca passphrase: %w", err)
		}
		return pass, nil
	}
	encrypted, err := caKeyEncrypted(caDir)
	if err != nil {
		return nil, err
	}
	if !encrypted {
		return nil, nil
	}
	if deps.CAUnlock == nil {
		return nil, fmt.Errorf("ca key is passphrase-protected but no passphrase source was provided")
	}
	pass, err := deps.CAUnlock()
	if err != nil {
		return nil, fmt.Errorf("obtain ca passphrase: %w", err)
	}
	dup := make([]byte, len(pass))
	copy(dup, pass)
	return dup, nil
}

// caKeyEncrypted reports whether the CA private key at caDir/ca is passphrase
// encrypted, without unlocking it.
func caKeyEncrypted(caDir string) (bool, error) {
	b, err := os.ReadFile(filepath.Join(caDir, "ca"))
	if err != nil {
		return false, fmt.Errorf("read ca key: %w", err)
	}
	_, err = ssh.ParsePrivateKey(b)
	if err == nil {
		return false, nil
	}
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		return true, nil
	}
	return false, fmt.Errorf("parse ca key: %w", err)
}

// pushPeerRekey delivers the new CA + cert to a single peer, branching on the
// peer's mode. Root-mode pushes ca.pub + cert and reloads sshd. User-mode
// rebuilds authorized_keys with the new CA's pubkey and pushes the new cert;
// no reload.
func pushPeerRekey(ctx context.Context, dial func(context.Context, string, sshpush.Options) (sshpush.Pusher, error), p *db.Peer, newCAPub, certBytes []byte, allowed []string, opts sshpush.Options) error {
	if p.Name == "" {
		return errors.New("empty host")
	}
	cl, err := dial(ctx, p.Name, opts)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer cl.Close()

	if p.Mode == db.ModeUser {
		akContent := userAuthorizedKeysLine(newCAPub, allowed)
		if err := cl.WriteFileAtomic(ctx, peerAuthorizedKeysRemotePath(p), akContent, fs.FileMode(0644)); err != nil {
			return fmt.Errorf("write authorized_keys: %w", err)
		}
		if err := cl.WriteFileAtomic(ctx, peerCertRemotePath(p), certBytes, fs.FileMode(0644)); err != nil {
			return fmt.Errorf("write peer cert: %w", err)
		}
	} else {
		if err := cl.WriteFileAtomic(ctx, "/etc/ssh/ca.pub", newCAPub, fs.FileMode(0644)); err != nil {
			return fmt.Errorf("write ca.pub: %w", err)
		}
		if err := cl.WriteFileAtomic(ctx, "/etc/ssh/peer_ed25519-cert.pub", certBytes, fs.FileMode(0644)); err != nil {
			return fmt.Errorf("write peer cert: %w", err)
		}
		if err := cl.ReloadSSHD(ctx); err != nil {
			return fmt.Errorf("reload sshd: %w", err)
		}
	}
	if err := cl.VerifyHealth(ctx); err != nil {
		return fmt.Errorf("verify health: %w", err)
	}
	return nil
}

// userAuthorizedKeysLine reconstructs a single cert-authority line from
// scratch using the new CA. Format contract: keep in sync with
// peerfiles.BuildUser (install-time tarball) and peerfiles.RewritePrincipals
// (incremental group edits) — manager is always first.
func userAuthorizedKeysLine(caPub []byte, principals []string) []byte {
	// Match the format produced by peerfiles.BuildUser. Keep the dedupe rules
	// in sync with peerfiles.RewritePrincipals: manager is always first.
	all := []string{"manager"}
	seen := map[string]struct{}{"manager": {}}
	for _, p := range principals {
		if _, ok := seen[p]; ok {
			continue
		}
		if p == "" {
			continue
		}
		seen[p] = struct{}{}
		all = append(all, p)
	}
	caTrim := trimTrailingNewline(caPub)
	line := []byte(`cert-authority,principals="`)
	for i, p := range all {
		if i > 0 {
			line = append(line, ',')
		}
		line = append(line, p...)
	}
	line = append(line, '"', ' ')
	line = append(line, caTrim...)
	line = append(line, '\n')
	return line
}

func trimTrailingNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func writeSelfRekey(dataDir string, self *db.Peer, newCAPub, selfCert []byte) error {
	if self.Mode == db.ModeUser {
		user := self.TargetUser
		if user == "" {
			user = "root"
		}
		base := filepath.Join(dataDir, "self", "home", user, ".ssh")
		if err := os.MkdirAll(base, 0700); err != nil {
			return err
		}
		ak := userAuthorizedKeysLine(newCAPub, nil)
		if err := writeFileAtomicLocal(filepath.Join(base, "authorized_keys"), ak, 0644); err != nil {
			return fmt.Errorf("write self authorized_keys: %w", err)
		}
		if err := writeFileAtomicLocal(filepath.Join(base, "id_ed25519-cert.pub"), selfCert, 0644); err != nil {
			return fmt.Errorf("write self cert: %w", err)
		}
		return nil
	}
	selfSSHDir := filepath.Join(dataDir, "self", "etc", "ssh")
	if err := writeFileAtomicLocal(filepath.Join(selfSSHDir, "ca.pub"), newCAPub, 0644); err != nil {
		return fmt.Errorf("write self ca.pub: %w", err)
	}
	if err := writeFileAtomicLocal(filepath.Join(selfSSHDir, "peer_ed25519-cert.pub"), selfCert, 0644); err != nil {
		return fmt.Errorf("write self cert: %w", err)
	}
	return nil
}
