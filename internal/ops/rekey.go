package ops

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/passphrase"
	"github.com/shudza/certhold/internal/peerfiles"
	"github.com/shudza/certhold/internal/sshpush"
)

type RekeyOptions struct {
	// Hostname is certhold's own peer name; its row anchors the self files.
	Hostname string
	// Exclude names peers to skip (revoke rotates around the revoked peer).
	Exclude map[string]bool
	// RotatePassphrase, when true, obtains a fresh passphrase for the new CA
	// key via NewPassphrase instead of reusing the current one.
	RotatePassphrase bool
	NewPassphrase    func() ([]byte, error)
}

// Rekey generates a new CA, signs new certs for every non-revoked peer except
// those in opts.Exclude, pushes them, then atomically swaps CA directories and
// updates ca_versions. Used by `certhold rekey` and by `certhold revoke` on
// user-mode peers (where there is no native KRL).
func Rekey(ctx context.Context, deps Deps, opts RekeyOptions) error {
	caDir := filepath.Join(deps.DataDir, "ca")
	oldCA, err := ca.LoadWithPassphrase(caDir, deps.CAUnlock)
	if err != nil {
		return fmt.Errorf("load ca: %w", err)
	}
	oldCAPub, _, _, _, err := ssh.ParseAuthorizedKey(oldCA.PublicKeyAuthorizedKey())
	if err != nil {
		return fmt.Errorf("parse old ca pubkey: %w", err)
	}

	// The per-instance key is stable across CA rekey — meta is never touched
	// here, only read.
	instanceKey, err := EnsureInstanceKey(ctx, deps.DB)
	if err != nil {
		return fmt.Errorf("ensure instance key: %w", err)
	}

	self, err := deps.DB.GetPeer(ctx, opts.Hostname)
	if err != nil {
		if errors.Is(err, db.ErrPeerNotFound) {
			return fmt.Errorf("certhold's own peer %q not found in db", opts.Hostname)
		}
		return fmt.Errorf("get self peer: %w", err)
	}

	peers, err := deps.DB.ListPeers(ctx)
	if err != nil {
		return fmt.Errorf("list peers: %w", err)
	}
	var others []db.Peer
	for _, p := range peers {
		if p.Revoked || p.Name == opts.Hostname || opts.Exclude[p.Name] {
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

	newCAPass, err := newCAPassphrase(caDir, deps, opts)
	if err != nil {
		return err
	}
	defer passphrase.Zero(newCAPass)
	newCA, err := ca.GenerateWithPassphrase(nextCADir, newCAPass)
	if err != nil {
		return fmt.Errorf("generate new ca: %w", err)
	}
	newCAPub := newCA.PublicKeyAuthorizedKey()

	pushOpts := SelfPushOptions(deps.DataDir, SelfIdent{
		TargetUser:  selfHomeUser(self),
		InstanceKey: instanceKey,
		Resolved:    true,
	}, deps.PeerPass)
	pushOpts.User = pushUser(self)

	var updated []string
	var failed []straggler
	for _, p := range others {
		groups, err := deps.DB.GetPeerGroups(ctx, p.Name)
		if err != nil {
			return deps.abortRekey(fmt.Errorf("get groups for %s: %w", p.Name, err), updated)
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey(p.AuthorizedKey)
		if err != nil {
			return deps.abortRekey(fmt.Errorf("parse pubkey for %s: %w", p.Name, err), updated)
		}
		principals := append([]string{p.Name}, groups...)
		certBytes, serial, err := newCA.SignCert(ca.SignOptions{
			Pubkey:     pk,
			KeyID:      p.Name,
			Principals: principals,
		})
		if err != nil {
			return deps.abortRekey(fmt.Errorf("sign cert for %s: %w", p.Name, err), updated)
		}

		if skip, notice := skipPushNotice(&p); skip {
			if err := deps.DB.SetPeerCert(ctx, p.Name, certBytes, serial); err != nil {
				return deps.abortRekey(fmt.Errorf("set peer cert %s: %w", p.Name, err), updated)
			}
			deps.info(p.Name, notice)
			updated = append(updated, p.Name)
			deps.emit(Event{Type: EventPeerDone, Peer: p.Name, Msg: fmt.Sprintf("rekeyed %s (serial %d)", p.Name, serial)})
			continue
		}

		peerForPush := p
		allowed, err := deps.DB.GetPeerAllowedGroups(ctx, p.Name)
		if err != nil {
			return deps.abortRekey(fmt.Errorf("get allowed groups for %s: %w", p.Name, err), updated)
		}
		hosts, err := deps.DB.ReachableHosts(ctx, p.Name)
		if err != nil {
			return deps.abortRekey(fmt.Errorf("reachable hosts for %s: %w", p.Name, err), updated)
		}
		configBlock := v2ConfigBlockForHosts(instanceKey, hosts)
		deps.emit(Event{Type: EventPeerStart, Peer: p.Name})
		if err := pushPeerRekey(ctx, deps.Dial, &peerForPush, oldCAPub, newCAPub, instanceKey, certBytes, allowed, configBlock, pushOpts); err != nil {
			failed = append(failed, straggler{name: p.Name, err: err})
			deps.emit(Event{Type: EventPeerFailed, Peer: p.Name, Err: err})
			continue
		}
		if err := deps.DB.SetPeerCert(ctx, p.Name, certBytes, serial); err != nil {
			return deps.abortRekey(fmt.Errorf("set peer cert %s: %w", p.Name, err), updated)
		}
		updated = append(updated, p.Name)
		deps.emit(Event{Type: EventPeerDone, Peer: p.Name, Msg: fmt.Sprintf("rekeyed %s (serial %d)", p.Name, serial)})
	}

	selfGroups, err := deps.DB.GetPeerGroups(ctx, opts.Hostname)
	if err != nil {
		return deps.abortRekey(fmt.Errorf("get groups for self: %w", err), updated)
	}
	selfPrincipals := []string{opts.Hostname, peerfiles.ManagerPrincipal}
	for _, g := range selfGroups {
		if g != peerfiles.ManagerPrincipal {
			selfPrincipals = append(selfPrincipals, g)
		}
	}
	selfPK, _, _, _, err := ssh.ParseAuthorizedKey(self.AuthorizedKey)
	if err != nil {
		return deps.abortRekey(fmt.Errorf("parse self pubkey: %w", err), updated)
	}
	selfCertBytes, selfSerial, err := newCA.SignCert(ca.SignOptions{
		Pubkey:     selfPK,
		KeyID:      opts.Hostname,
		Principals: selfPrincipals,
	})
	if err != nil {
		return deps.abortRekey(fmt.Errorf("sign self cert: %w", err), updated)
	}

	if err := writeSelfRekey(deps.DataDir, self, oldCAPub, newCAPub, instanceKey, selfCertBytes); err != nil {
		return deps.abortRekey(fmt.Errorf("update self files: %w", err), updated)
	}
	if err := deps.DB.SetPeerCert(ctx, opts.Hostname, selfCertBytes, selfSerial); err != nil {
		return deps.abortRekey(fmt.Errorf("set self peer cert: %w", err), updated)
	}
	updated = append(updated, opts.Hostname)
	deps.emit(Event{Type: EventPeerDone, Peer: opts.Hostname, Msg: fmt.Sprintf("rekeyed %s (serial %d)", opts.Hostname, selfSerial)})

	timestamp := time.Now().UTC().Format("20060102T150405")
	oldCADir := filepath.Join(deps.DataDir, fmt.Sprintf("ca.old.%s", timestamp))
	// Two rekeys in the same wall-clock second (e.g. a TUI batch revoke) would
	// otherwise collide on this second-resolution archive name and fail the
	// non-empty-dir rename; disambiguate with a numeric suffix.
	for i := 1; ; i++ {
		if _, err := os.Stat(oldCADir); errors.Is(err, os.ErrNotExist) {
			break
		} else if err != nil {
			return fmt.Errorf("stat old ca archive: %w", err)
		}
		oldCADir = filepath.Join(deps.DataDir, fmt.Sprintf("ca.old.%s.%d", timestamp, i))
	}
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
	if err := deps.DB.BumpFleetRev(ctx); err != nil {
		return fmt.Errorf("bump fleet_rev: %w", err)
	}

	deps.info("", fmt.Sprintf("Rekey complete: %d peers rotated, CA version %d active, old CA archived at %s", len(updated), newVer, oldCADir))
	deps.reportStragglers(failed, oldCADir)
	return nil
}

// abortRekey emits the historical stderr abort lines as EventWarn and returns
// the cause unchanged.
func (d Deps) abortRekey(cause error, updated []string) error {
	d.warn("", fmt.Sprintf("rekey aborted: %v", cause))
	if len(updated) > 0 {
		d.warn("", fmt.Sprintf("peers already rotated to new CA (recovery may be required): %v", updated))
	}
	return cause
}

// straggler is a peer the rekey could not reach: its push/dial failed, so it
// keeps trusting the previous CA and its DB cert_serial was left untouched.
type straggler struct {
	name string
	err  error
}

// reportStragglers emits a prominent warning naming each unreached peer and the
// archived old CA dir to use for recovery. Partial success deliberately returns
// nil from Rekey (so a single down host does not fail rekey/revoke in
// automation); this warning plus the summary line are the only signal.
func (d Deps) reportStragglers(failed []straggler, oldCADir string) {
	if len(failed) == 0 {
		return
	}
	d.warn("", fmt.Sprintf("\nWARNING: rekey could not reach %d peer(s); they STILL TRUST THE PREVIOUS CA and were NOT rotated:", len(failed)))
	for _, s := range failed {
		d.warn(s.name, fmt.Sprintf("  - %s: %v", s.name, s.err))
	}
	d.warn("", fmt.Sprintf("These peers will reject this manager's new-CA cert until rotated. Recover with the archived old CA at %s:", oldCADir))
	d.warn("", fmt.Sprintf("  mint a manager cert from %s/ca to reach each straggler, push the new CA trust + new cert, then re-run rekey.", oldCADir))
}

// newCAPassphrase decides the passphrase for the freshly generated CA key.
// When RotatePassphrase is set it obtains a fresh one via opts.NewPassphrase
// (defaulting to a confirmed prompt). Otherwise it mirrors the old CA's
// protection: an encrypted old CA reuses the same (memoized) passphrase; a
// plaintext old CA yields a nil passphrase so the new key is also plaintext
// (no spurious prompt).
func newCAPassphrase(caDir string, deps Deps, opts RekeyOptions) ([]byte, error) {
	if opts.RotatePassphrase {
		prompt := opts.NewPassphrase
		if prompt == nil {
			prompt = func() ([]byte, error) {
				return passphrase.PromptConfirm("New CA passphrase: ", "")
			}
		}
		pass, err := prompt()
		if err != nil {
			return nil, fmt.Errorf("read new ca passphrase: %w", err)
		}
		return pass, nil
	}
	encrypted, err := CAKeyEncrypted(caDir)
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
	return pass, nil
}

// CAKeyEncrypted reports whether the CA private key at caDir/ca is passphrase
// encrypted, without unlocking it.
func CAKeyEncrypted(caDir string) (bool, error) {
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

// pushPeerRekey delivers the new CA + cert to a single peer. It swaps this
// instance's cert-authority line in <home>/.ssh/authorized_keys (preserving any
// other instance's lines), pushes the namespaced cert, and splices the keyed
// client-config block; no reload.
func pushPeerRekey(ctx context.Context, dial DialFn, p *db.Peer, oldCAPub ssh.PublicKey, newCAPub []byte, instanceKey string, certBytes []byte, allowed []string, configBlock string, opts sshpush.Options) error {
	if p.Name == "" {
		return errors.New("empty host")
	}
	cl, err := dial(ctx, p.DialHost(), opts)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer cl.Close()

	akPath := PeerAuthorizedKeysRemotePath(p)
	newLine := userAuthorizedKeysLine(newCAPub, allowed)
	existing, err := cl.ReadFile(ctx, akPath)
	if err != nil {
		return fmt.Errorf("read authorized_keys: %w", err)
	}
	akContent := peerfiles.ReplaceCALine(existing, oldCAPub, newLine)
	if err := cl.WriteFileAtomic(ctx, akPath, akContent, fs.FileMode(0644)); err != nil {
		return fmt.Errorf("write authorized_keys: %w", err)
	}
	if err := cl.WriteFileAtomic(ctx, PeerCertRemotePath(p, instanceKey), certBytes, fs.FileMode(0644)); err != nil {
		return fmt.Errorf("write peer cert: %w", err)
	}
	if err := cl.SpliceConfigBlock(ctx, peerfiles.PathsFor(p.TargetUser, instanceKey).ConfigTarget, instanceKey, configBlock); err != nil {
		return fmt.Errorf("splice ssh config: %w", err)
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
	all := []string{peerfiles.ManagerPrincipal}
	seen := map[string]struct{}{peerfiles.ManagerPrincipal: {}}
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

func writeSelfRekey(dataDir string, self *db.Peer, oldCAPub ssh.PublicKey, newCAPub []byte, instanceKey string, selfCert []byte) error {
	homeRel := strings.TrimPrefix(peerfiles.HomeOf(selfHomeUser(self)), "/")
	base := filepath.Join(dataDir, "self", homeRel, ".ssh")
	if err := os.MkdirAll(base, 0700); err != nil {
		return err
	}
	newLine := userAuthorizedKeysLine(newCAPub, nil)
	akPath := filepath.Join(base, "authorized_keys")
	existing, _ := os.ReadFile(akPath)
	if err := writeFileAtomicLocal(akPath, peerfiles.ReplaceCALine(existing, oldCAPub, newLine), 0644); err != nil {
		return fmt.Errorf("write self authorized_keys: %w", err)
	}
	if err := writeFileAtomicLocal(filepath.Join(base, peerfiles.V2CertFileName(instanceKey)), selfCert, 0644); err != nil {
		return fmt.Errorf("write self cert: %w", err)
	}
	return nil
}
