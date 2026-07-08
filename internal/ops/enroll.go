package ops

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
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
	// BaseURL is the enroll endpoint base baked into the one-liner and the
	// peer's pull conf; the CLI resolves it from flag/env/persisted file.
	BaseURL string
}

// EnrollResult carries the minted enrollment: the one-shot token, the curl
// one-liner (no trailing newline) and the peer name.
type EnrollResult struct {
	Token    string
	OneLiner string
	PeerName string
}

// MintEnroll mints an enrollment: generates the peer key, signs the cert at
// mint time, builds the install tarball, and commits peer row + groups +
// allowed groups + token + fleet-rev bump in a single transaction (a failure
// rolls back all of them). It returns data and prints nothing.
func MintEnroll(ctx context.Context, deps Deps, spec EnrollSpec) (EnrollResult, error) {
	if err := peerfiles.ValidateDialAddress(spec.Address); err != nil {
		return EnrollResult{}, err
	}

	instanceKey, err := EnsureInstanceKey(ctx, deps.DB)
	if err != nil {
		return EnrollResult{}, fmt.Errorf("ensure instance key: %w", err)
	}

	if _, err := deps.DB.GetPeer(ctx, spec.Name); err == nil {
		return EnrollResult{}, fmt.Errorf("peer %q already exists", spec.Name)
	} else if !errors.Is(err, db.ErrPeerNotFound) {
		return EnrollResult{}, fmt.Errorf("lookup peer: %w", err)
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

	principals := append([]string{spec.Name}, spec.Groups...)
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

	hosts, err := reachableHostEntries(ctx, deps.DB, spec.Name, spec.Groups)
	if err != nil {
		return EnrollResult{}, fmt.Errorf("reachable hosts: %w", err)
	}

	conf := fmt.Sprintf("BASE_URL=%s\nPULL_TOKEN=%s\nINSTANCE_KEY=%s\nPEER_NAME=%s\nLAST_REV=0\n",
		spec.BaseURL, pullToken, instanceKey, spec.Name)

	tarball, err := peerfiles.BuildUser(peerfiles.UserPeerFiles{
		TargetUser:  spec.User,
		PrivKey:     priv,
		CertPub:     certBytes,
		CAPub:       caObj.PublicKeyAuthorizedKey(),
		Principals:  spec.Groups,
		InstanceKey: instanceKey,
		NoInbound:   spec.Client,
		Hosts:       hosts,
		CLIScript:   clientcli.Script,
		Conf:        []byte(conf),
	})
	if err != nil {
		return EnrollResult{}, fmt.Errorf("build tarball: %w", err)
	}

	if err := deps.DB.WithTx(ctx, func(tx *db.Tx) error {
		if err := tx.InsertPeer(ctx, spec.Name, serial, fingerprint, pubAuth, spec.User, !spec.Client, pullToken); err != nil {
			return fmt.Errorf("insert peer: %w", err)
		}
		if err := tx.SetPeerCert(ctx, spec.Name, certBytes, serial); err != nil {
			return fmt.Errorf("set peer cert: %w", err)
		}
		if spec.Address != "" {
			if err := tx.SetPeerAddress(ctx, spec.Name, spec.Address); err != nil {
				return fmt.Errorf("set peer address: %w", err)
			}
		}
		for _, g := range spec.Groups {
			exists, err := tx.GroupExists(ctx, g)
			if err != nil {
				return fmt.Errorf("check group %q: %w", g, err)
			}
			if !exists {
				return fmt.Errorf("group %q does not exist (run \"certhold group create %s\" first)", g, g)
			}
		}
		if err := tx.SetPeerGroups(ctx, spec.Name, spec.Groups); err != nil {
			return fmt.Errorf("set peer groups: %w", err)
		}
		if !spec.Client {
			if err := tx.SetPeerAllowedGroups(ctx, spec.Name, spec.Allowed); err != nil {
				return fmt.Errorf("set peer allowed groups: %w", err)
			}
		}
		if err := tx.InsertToken(ctx, tok, spec.Name, strings.Join(spec.Groups, ","), spec.User, tarball); err != nil {
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
	}, nil
}

// reachableHostEntries mirrors db.ReachableHosts for a peer that is not yet
// inserted: its groups are known up front, so the reachable set is computed
// before the enrollment transaction opens (the single-connection DB cannot
// serve reads while a tx is held).
func reachableHostEntries(ctx context.Context, d *db.DB, peerName string, groups []string) ([]peerfiles.HostEntry, error) {
	seen := make(map[string]struct{})
	var names []string
	for _, g := range groups {
		allowedBy, err := d.GetGroupAllowedBy(ctx, g)
		if err != nil {
			return nil, err
		}
		for _, n := range allowedBy {
			if n == peerName {
				continue
			}
			if _, ok := seen[n]; ok {
				continue
			}
			seen[n] = struct{}{}
			names = append(names, n)
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
