package ops

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/clientcli"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/passphrase"
	"github.com/shudza/certhold/internal/peerfiles"
	"github.com/shudza/certhold/internal/token"
)

// EnrollSpec describes one peer enrollment to mint.
type EnrollSpec struct {
	Name    string
	Groups  []string
	Allowed []string
	User    string
	Address string
	Client  bool
	// ClientSet marks Client as an explicit operator choice. It only matters
	// when Name is an existing peer (a re-enroll): unset means the peer keeps
	// its current inbound/client configuration. New-name enrolls read Client
	// directly, as before.
	ClientSet bool
	// AllowedSet marks Allowed as an explicit operator choice on a re-enroll
	// (the TUI form's allowed-inbound picker): the staged commit then applies
	// it. Unset keeps the existing behavior — an inbound peer's curated allowed
	// set is preserved, a client->inbound transition seeds allowed = groups.
	// New-name enrolls read Allowed directly, as before.
	AllowedSet bool
	// BaseURL is the enroll endpoint base baked into the one-liner and the
	// peer's pull conf; the CLI resolves it from flag/env/persisted file.
	BaseURL string
}

// EnrollResult carries the minted enrollment: the one-shot token, the curl
// one-liner (no trailing newline) and the peer name. Reenroll marks the
// existing-peer path (staged mint, nothing committed yet); Client is the
// enrollment's effective client-style flag after re-enroll defaulting.
type EnrollResult struct {
	Token    string
	OneLiner string
	PeerName string
	Reenroll bool
	Client   bool
}

// MintEnroll mints an enrollment. For a NEW name it generates the peer key,
// signs the cert at mint time, builds the install tarball, and commits peer row
// + groups + allowed groups + token + fleet-rev bump in a single transaction (a
// failure rolls back all of them). For an EXISTING name it is a supported
// in-place reconfigure: unset spec fields default to the peer's current
// configuration, a fresh keypair+cert+pull token are minted, and everything is
// STAGED on the token row — the peer row is not touched and fleet_rev not
// bumped until the one-liner is redeemed (ConsumeToken commits the staged
// material). A re-enroll mint supersedes any prior unconsumed token for the
// peer. It returns data and prints nothing.
func MintEnroll(ctx context.Context, deps Deps, spec EnrollSpec) (EnrollResult, error) {
	if err := peerfiles.ValidateDialAddress(spec.Address); err != nil {
		return EnrollResult{}, err
	}

	instanceKey, err := EnsureInstanceKey(ctx, deps.DB)
	if err != nil {
		return EnrollResult{}, fmt.Errorf("ensure instance key: %w", err)
	}

	existing, err := deps.DB.GetPeer(ctx, spec.Name)
	switch {
	case err == nil:
		if gerr := guardNotSelfPeer(ctx, deps.DB, "re-enroll", spec.Name, ""); gerr != nil {
			return EnrollResult{}, gerr
		}
		// Second signal beyond the hostname check: the self cert on disk names
		// the manager row authoritatively even when `init --hostname` differs
		// from os.Hostname().
		if selfName := selfCertKeyID(deps.DataDir, instanceKey); selfName != "" && selfName == spec.Name {
			return EnrollResult{}, fmt.Errorf("refusing to re-enroll certhold's own peer %q: this is the manager's self row; deleting or altering it breaks rekey, revoke --rekey and all pushes", spec.Name)
		}
		if existing.Revoked {
			return EnrollResult{}, fmt.Errorf("peer %q is revoked; run \"certhold remove %s\" first if it should be re-enrolled", spec.Name, spec.Name)
		}
	case errors.Is(err, db.ErrPeerNotFound):
		existing = nil
		if len(spec.Groups) == 0 {
			return EnrollResult{}, fmt.Errorf("--groups is required to enroll a new peer")
		}
	default:
		return EnrollResult{}, fmt.Errorf("lookup peer: %w", err)
	}

	// Re-enroll defaulting: unset flags keep the peer's current configuration.
	groups, allowed, client := spec.Groups, spec.Allowed, spec.Client
	user, address := spec.User, spec.Address
	if existing != nil {
		if !spec.ClientSet {
			client = !existing.Inbound
		}
		if len(groups) == 0 {
			if groups, err = deps.DB.GetPeerGroups(ctx, spec.Name); err != nil {
				return EnrollResult{}, fmt.Errorf("get peer groups: %w", err)
			}
			if len(groups) == 0 {
				return EnrollResult{}, fmt.Errorf("peer %q has no groups; pass --groups to re-enroll it", spec.Name)
			}
		}
		if user == "" {
			user = existing.TargetUser
		}
		// The trust line the bundle stages mirrors what the allowed set will be
		// after commit: an explicit choice (AllowedSet) wins; otherwise an
		// inbound->inbound re-enroll preserves the current allow-list (the
		// install leaves an already-present line alone anyway) and a
		// client->inbound transition starts symmetric, like a fresh enroll.
		switch {
		case spec.AllowedSet:
			allowed = spec.Allowed
		case existing.Inbound && !client:
			if allowed, err = deps.DB.GetPeerAllowedGroups(ctx, spec.Name); err != nil {
				return EnrollResult{}, fmt.Errorf("get peer allowed groups: %w", err)
			}
		default:
			allowed = groups
		}
	}

	caObj, err := ca.LoadWithPassphrase(filepath.Join(deps.DataDir, "ca"), deps.CAUnlock)
	if err != nil {
		return EnrollResult{}, fmt.Errorf("load ca: %w", err)
	}

	priv, pubAuth, sshPub, err := ca.GeneratePeerKey()
	if err != nil {
		return EnrollResult{}, fmt.Errorf("generate peer key: %w", err)
	}
	defer passphrase.Zero(priv)

	principals := certPrincipals(spec.Name, groups, false)
	certBytes, serial, err := caObj.SignCert(ca.SignOptions{
		Pubkey:     sshPub,
		KeyID:      spec.Name,
		Principals: principals,
	})
	if err != nil {
		return EnrollResult{}, fmt.Errorf("sign cert: %w", err)
	}

	fingerprint := ssh.FingerprintSHA256(sshPub)

	pullToken, err := token.Generate()
	if err != nil {
		return EnrollResult{}, fmt.Errorf("generate pull token: %w", err)
	}

	tok, err := token.Generate()
	if err != nil {
		return EnrollResult{}, fmt.Errorf("generate token: %w", err)
	}

	hosts, err := reachableHostEntries(ctx, deps.DB, spec.Name, groups)
	if err != nil {
		return EnrollResult{}, fmt.Errorf("reachable hosts: %w", err)
	}

	conf := fmt.Sprintf("BASE_URL=%s\nPULL_TOKEN=%s\nINSTANCE_KEY=%s\nPEER_NAME=%s\nLAST_REV=0\n",
		spec.BaseURL, pullToken, instanceKey, spec.Name)

	tarball, err := peerfiles.BuildUser(peerfiles.UserPeerFiles{
		TargetUser:  user,
		PrivKey:     priv,
		CertPub:     certBytes,
		CAPub:       caObj.PublicKeyAuthorizedKey(),
		Principals:  allowed,
		InstanceKey: instanceKey,
		NoInbound:   client,
		Hosts:       hosts,
		CLIScript:   clientcli.Script,
		Conf:        []byte(conf),
	})
	if err != nil {
		return EnrollResult{}, fmt.Errorf("build tarball: %w", err)
	}

	if err := deps.DB.WithTx(ctx, func(tx *db.Tx) error {
		checkNames := groups
		if spec.AllowedSet {
			checkNames = append(append([]string(nil), groups...), allowed...)
		}
		seen := make(map[string]struct{}, len(checkNames))
		for _, g := range checkNames {
			if _, ok := seen[g]; ok {
				continue
			}
			seen[g] = struct{}{}
			exists, err := tx.GroupExists(ctx, g)
			if err != nil {
				return fmt.Errorf("check group %q: %w", g, err)
			}
			if !exists {
				return fmt.Errorf("group %q does not exist (run \"certhold group create %s\" first)", g, g)
			}
		}
		if existing != nil {
			if err := tx.DeleteUnconsumedPeerTokens(ctx, spec.Name); err != nil {
				return err
			}
			return tx.InsertReenrollToken(ctx, tok, spec.Name, strings.Join(groups, ","), user, tarball,
				db.StagedReenroll{
					AuthorizedKey: pubAuth,
					Fingerprint:   fingerprint,
					Serial:        serial,
					Cert:          certBytes,
					PullToken:     pullToken,
					Inbound:       !client,
					Address:       address,
					Allowed:       allowed,
					AllowedSet:    spec.AllowedSet,
				})
		}
		if err := tx.InsertPeer(ctx, spec.Name, serial, fingerprint, pubAuth, user, !client, pullToken); err != nil {
			return fmt.Errorf("insert peer: %w", err)
		}
		if err := tx.SetPeerCert(ctx, spec.Name, certBytes, serial); err != nil {
			return fmt.Errorf("set peer cert: %w", err)
		}
		if address != "" {
			if err := tx.SetPeerAddress(ctx, spec.Name, address); err != nil {
				return fmt.Errorf("set peer address: %w", err)
			}
		}
		if err := tx.SetPeerGroups(ctx, spec.Name, groups); err != nil {
			return fmt.Errorf("set peer groups: %w", err)
		}
		if !client {
			if err := tx.SetPeerAllowedGroups(ctx, spec.Name, allowed); err != nil {
				return fmt.Errorf("set peer allowed groups: %w", err)
			}
		}
		if err := tx.InsertToken(ctx, tok, spec.Name, strings.Join(groups, ","), user, tarball); err != nil {
			return fmt.Errorf("insert token: %w", err)
		}
		if err := tx.BumpFleetRev(ctx); err != nil {
			return fmt.Errorf("bump fleet rev: %w", err)
		}
		return nil
	}); err != nil {
		return EnrollResult{}, err
	}

	return EnrollResult{
		Token:    tok,
		OneLiner: fmt.Sprintf("curl -kfsSL %s/enroll/%s.sh | bash", spec.BaseURL, tok),
		PeerName: spec.Name,
		Reenroll: existing != nil,
		Client:   client,
	}, nil
}

// reachableHostEntries mirrors db.ReachableHosts for a peer that is not yet
// inserted: its groups are known up front, so the reachable set is computed
// before the enrollment transaction opens (the single-connection DB cannot
// serve reads while a tx is held). It must stay in sync with db.ReachableHosts:
// peers that allow one of the groups, OR — when groups contain the manager
// principal — every inbound non-revoked peer, deduped and ordered by name.
func reachableHostEntries(ctx context.Context, d *db.DB, peerName string, groups []string) ([]peerfiles.HostEntry, error) {
	seen := make(map[string]struct{})
	var names []string
	add := func(n string) {
		if n == peerName {
			return
		}
		if _, ok := seen[n]; ok {
			return
		}
		seen[n] = struct{}{}
		names = append(names, n)
	}
	for _, g := range groups {
		allowedBy, err := d.GetGroupAllowedBy(ctx, g)
		if err != nil {
			return nil, err
		}
		for _, n := range allowedBy {
			add(n)
		}
	}
	if slices.Contains(groups, peerfiles.ManagerPrincipal) {
		peers, err := d.ListPeers(ctx)
		if err != nil {
			return nil, err
		}
		for _, p := range peers {
			if p.Inbound && !p.Revoked {
				add(p.Name)
			}
		}
	}
	sort.Strings(names)

	hosts := make([]peerfiles.HostEntry, 0, len(names))
	for _, n := range names {
		p, err := d.GetPeer(ctx, n)
		if err != nil {
			return nil, err
		}
		if p.Revoked || !p.Inbound {
			continue
		}
		hosts = append(hosts, peerfiles.HostEntry{Name: p.Name, Address: p.Address, User: p.TargetUser})
	}
	return hosts, nil
}
