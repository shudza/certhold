package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/ca"
	"github.com/shudza/certhold/internal/db"
	"github.com/shudza/certhold/internal/peerfiles"
	"github.com/shudza/certhold/internal/sshpush"
)

// groupDial is overridden in tests.
var groupDial = func(ctx context.Context, host string, opts sshpush.Options) (sshpush.Pusher, error) {
	return sshpush.Dial(ctx, host, opts)
}

func newGroupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "group",
		Short: "Manage groups and group memberships",
	}
	cmd.AddCommand(newGroupAllowCmd(), newGroupDisallowCmd(), newGroupCreateCmd(), newGroupShowCmd(), newGroupDeleteCmd(), newGroupRenameCmd())
	return cmd
}

func newGroupRenameCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rename <old> <new>",
		Short: "Rename a group and push the cascading rewrite to every affected peer",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGroupRename(cmd, args[0], args[1])
		},
	}
}

func runGroupRename(cmd *cobra.Command, oldName, newName string) error {
	newName = strings.TrimSpace(newName)
	if oldName == peerfiles.ManagerPrincipal || newName == peerfiles.ManagerPrincipal {
		return fmt.Errorf("group %q is reserved", peerfiles.ManagerPrincipal)
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

	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	if oldName == newName {
		exists, err := d.GroupExists(ctx, oldName)
		if err != nil {
			return fmt.Errorf("group exists: %w", err)
		}
		if !exists {
			return fmt.Errorf("group %q does not exist", oldName)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "group %q renamed (no change)\n", oldName)
		return nil
	}

	members, err := d.GetGroupMembers(ctx, oldName)
	if err != nil {
		return fmt.Errorf("get group members: %w", err)
	}
	allowedBy, err := d.GetGroupAllowedBy(ctx, oldName)
	if err != nil {
		return fmt.Errorf("get group allowed-by: %w", err)
	}

	memberSet := make(map[string]struct{}, len(members))
	for _, m := range members {
		memberSet[m] = struct{}{}
	}
	allowedBySet := make(map[string]struct{}, len(allowedBy))
	for _, a := range allowedBy {
		allowedBySet[a] = struct{}{}
	}
	affectedSet := make(map[string]struct{}, len(members)+len(allowedBy))
	for k := range memberSet {
		affectedSet[k] = struct{}{}
	}
	for k := range allowedBySet {
		affectedSet[k] = struct{}{}
	}

	if err := d.RenameGroup(ctx, oldName, newName); err != nil {
		switch {
		case errors.Is(err, db.ErrGroupNotFound):
			return fmt.Errorf("group %q does not exist", oldName)
		case errors.Is(err, db.ErrGroupExists):
			return fmt.Errorf("group %q already exists", newName)
		case errors.Is(err, db.ErrInvalidGroupName):
			return fmt.Errorf("invalid group name %q", newName)
		default:
			return fmt.Errorf("rename group: %w", err)
		}
	}

	if len(affectedSet) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "group renamed: %q → %q (no peers affected)\n", oldName, newName)
		return nil
	}

	affected := make([]string, 0, len(affectedSet))
	for k := range affectedSet {
		affected = append(affected, k)
	}
	sort.Strings(affected)

	caUnlock := newCAUnlocker()
	defer caUnlock.Zero()
	peerUnlock := newPeerUnlocker()
	defer peerUnlock.Zero()

	var caObj *ca.CA
	if len(members) > 0 {
		caObj, err = ca.LoadWithPassphrase(filepath.Join(dataDir, "ca"), caUnlock.get)
		if err != nil {
			return fmt.Errorf("load ca: %w", err)
		}
	}

	caPubBytes, err := ca.LoadPublicKey(filepath.Join(dataDir, "ca"))
	if err != nil {
		return fmt.Errorf("load ca public key: %w", err)
	}
	caPub, _, _, _, err := ssh.ParseAuthorizedKey(caPubBytes)
	if err != nil {
		return fmt.Errorf("parse ca pubkey: %w", err)
	}

	instanceKey, err := EnsureInstanceKey(ctx, d)
	if err != nil {
		return fmt.Errorf("ensure instance key: %w", err)
	}

	self := resolveSelfIdent(ctx, d)
	var stragglers []string
	var touched []string

	for _, peerName := range affected {
		peer, err := d.GetPeer(ctx, peerName)
		if err != nil {
			if errors.Is(err, db.ErrPeerNotFound) {
				continue
			}
			return fmt.Errorf("get peer %q: %w", peerName, err)
		}
		if peer.Revoked {
			continue
		}

		pushOpts := selfPushOptions(dataDir, self, peerUnlock.get)
		pushOpts.User = pushUser(peer)
		host := peer.DialHost()
		pusher, err := groupDial(ctx, host, pushOpts)
		if err != nil {
			stragglers = append(stragglers, peerName)
			continue
		}

		if _, isMember := memberSet[peerName]; isMember {
			currentGroups, err := d.GetPeerGroups(ctx, peerName)
			if err != nil {
				pusher.Close()
				return fmt.Errorf("get peer groups %q: %w", peerName, err)
			}

			pk, _, _, _, err := ssh.ParseAuthorizedKey(peer.AuthorizedKey)
			if err != nil {
				pusher.Close()
				return fmt.Errorf("parse peer pubkey %q: %w", peerName, err)
			}
			principals := append([]string{peerName}, currentGroups...)
			certBytes, serial, err := caObj.SignCert(ca.SignOptions{
				Pubkey:     pk,
				KeyID:      peerName,
				Principals: principals,
			})
			if err != nil {
				pusher.Close()
				return fmt.Errorf("sign cert %q: %w", peerName, err)
			}
			if err := d.UpdatePeerCertSerial(ctx, peerName, serial); err != nil {
				pusher.Close()
				return fmt.Errorf("update cert serial %q: %w", peerName, err)
			}

			certPath := peerCertRemotePath(peer, instanceKey)
			if err := pusher.WriteFileAtomic(ctx, certPath, certBytes, fs.FileMode(0644)); err != nil {
				stragglers = append(stragglers, peerName)
				pusher.Close()
				continue
			}
		}

		if _, isAllow := allowedBySet[peerName]; isAllow {
			currentAllowed, err := d.GetPeerAllowedGroups(ctx, peerName)
			if err != nil {
				pusher.Close()
				return fmt.Errorf("get peer allowed groups %q: %w", peerName, err)
			}
			remote := peerAuthorizedKeysRemotePath(peer)
			existing, err := pusher.ReadFile(ctx, remote)
			if err != nil {
				stragglers = append(stragglers, peerName)
				pusher.Close()
				continue
			}
			newContent, err := peerfiles.RewritePrincipals(existing, caPub, currentAllowed)
			if err != nil {
				stragglers = append(stragglers, peerName)
				pusher.Close()
				continue
			}
			if err := pusher.WriteFileAtomic(ctx, remote, newContent, fs.FileMode(0644)); err != nil {
				stragglers = append(stragglers, peerName)
				pusher.Close()
				continue
			}
		}

		if err := pusher.VerifyHealth(ctx); err != nil {
			stragglers = append(stragglers, peerName)
			pusher.Close()
			continue
		}
		pusher.Close()
		touched = append(touched, peerName)
	}

	if len(stragglers) > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "peers with unfinished pushes (DB rename already committed): %s\n", strings.Join(stragglers, ","))
		return fmt.Errorf("group rename incomplete: %d straggler(s)", len(stragglers))
	}

	fmt.Fprintf(cmd.OutOrStdout(), "group renamed: %q → %q (peers updated: %s)\n", oldName, newName, strings.Join(touched, ","))
	return nil
}

func newGroupDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a group and push the cascading removal to every affected peer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGroupDelete(cmd, args[0])
		},
	}
}

func runGroupDelete(cmd *cobra.Command, name string) error {
	if name == peerfiles.ManagerPrincipal {
		return fmt.Errorf("group %q is reserved", name)
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

	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	exists, err := d.GroupExists(ctx, name)
	if err != nil {
		return fmt.Errorf("group exists: %w", err)
	}
	if !exists {
		return fmt.Errorf("group %q does not exist", name)
	}

	members, err := d.GetGroupMembers(ctx, name)
	if err != nil {
		return fmt.Errorf("get group members: %w", err)
	}
	allowedBy, err := d.GetGroupAllowedBy(ctx, name)
	if err != nil {
		return fmt.Errorf("get group allowed-by: %w", err)
	}

	memberSet := make(map[string]struct{}, len(members))
	for _, m := range members {
		memberSet[m] = struct{}{}
	}
	allowedBySet := make(map[string]struct{}, len(allowedBy))
	for _, a := range allowedBy {
		allowedBySet[a] = struct{}{}
	}
	affectedSet := make(map[string]struct{}, len(members)+len(allowedBy))
	for k := range memberSet {
		affectedSet[k] = struct{}{}
	}
	for k := range allowedBySet {
		affectedSet[k] = struct{}{}
	}

	if len(affectedSet) == 0 {
		if err := d.DeleteGroup(ctx, name); err != nil {
			return fmt.Errorf("delete group: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "group %q deleted (no peers affected)\n", name)
		return nil
	}

	affected := make([]string, 0, len(affectedSet))
	for k := range affectedSet {
		affected = append(affected, k)
	}
	sort.Strings(affected)

	caUnlock := newCAUnlocker()
	defer caUnlock.Zero()
	peerUnlock := newPeerUnlocker()
	defer peerUnlock.Zero()

	var caObj *ca.CA
	if len(members) > 0 {
		caObj, err = ca.LoadWithPassphrase(filepath.Join(dataDir, "ca"), caUnlock.get)
		if err != nil {
			return fmt.Errorf("load ca: %w", err)
		}
	}

	caPubBytes, err := ca.LoadPublicKey(filepath.Join(dataDir, "ca"))
	if err != nil {
		return fmt.Errorf("load ca public key: %w", err)
	}
	caPub, _, _, _, err := ssh.ParseAuthorizedKey(caPubBytes)
	if err != nil {
		return fmt.Errorf("parse ca pubkey: %w", err)
	}

	instanceKey, err := EnsureInstanceKey(ctx, d)
	if err != nil {
		return fmt.Errorf("ensure instance key: %w", err)
	}

	self := resolveSelfIdent(ctx, d)
	var stragglers []string
	var touched []string

	for _, peerName := range affected {
		peer, err := d.GetPeer(ctx, peerName)
		if err != nil {
			if errors.Is(err, db.ErrPeerNotFound) {
				continue
			}
			return fmt.Errorf("get peer %q: %w", peerName, err)
		}
		if peer.Revoked {
			continue
		}

		pushOpts := selfPushOptions(dataDir, self, peerUnlock.get)
		pushOpts.User = pushUser(peer)
		host := peer.DialHost()
		pusher, err := groupDial(ctx, host, pushOpts)
		if err != nil {
			stragglers = append(stragglers, peerName)
			continue
		}

		if _, isMember := memberSet[peerName]; isMember {
			currentGroups, err := d.GetPeerGroups(ctx, peerName)
			if err != nil {
				pusher.Close()
				return fmt.Errorf("get peer groups %q: %w", peerName, err)
			}
			newGroups := removeStr(currentGroups, name)

			pk, _, _, _, err := ssh.ParseAuthorizedKey(peer.AuthorizedKey)
			if err != nil {
				pusher.Close()
				return fmt.Errorf("parse peer pubkey %q: %w", peerName, err)
			}
			principals := append([]string{peerName}, newGroups...)
			certBytes, serial, err := caObj.SignCert(ca.SignOptions{
				Pubkey:     pk,
				KeyID:      peerName,
				Principals: principals,
			})
			if err != nil {
				pusher.Close()
				return fmt.Errorf("sign cert %q: %w", peerName, err)
			}

			if err := d.SetPeerGroups(ctx, peerName, newGroups); err != nil {
				pusher.Close()
				return fmt.Errorf("set peer groups %q: %w", peerName, err)
			}
			if err := d.UpdatePeerCertSerial(ctx, peerName, serial); err != nil {
				pusher.Close()
				return fmt.Errorf("update cert serial %q: %w", peerName, err)
			}

			certPath := peerCertRemotePath(peer, instanceKey)
			if err := pusher.WriteFileAtomic(ctx, certPath, certBytes, fs.FileMode(0644)); err != nil {
				stragglers = append(stragglers, peerName)
				pusher.Close()
				continue
			}
		}

		if _, isAllow := allowedBySet[peerName]; isAllow {
			currentAllowed, err := d.GetPeerAllowedGroups(ctx, peerName)
			if err != nil {
				pusher.Close()
				return fmt.Errorf("get peer allowed groups %q: %w", peerName, err)
			}
			newAllowed := removeStr(currentAllowed, name)
			if err := d.SetPeerAllowedGroups(ctx, peerName, newAllowed); err != nil {
				pusher.Close()
				return fmt.Errorf("set peer allowed groups %q: %w", peerName, err)
			}

			remote := peerAuthorizedKeysRemotePath(peer)
			existing, err := pusher.ReadFile(ctx, remote)
			if err != nil {
				stragglers = append(stragglers, peerName)
				pusher.Close()
				continue
			}
			newContent, err := peerfiles.RewritePrincipals(existing, caPub, newAllowed)
			if err != nil {
				stragglers = append(stragglers, peerName)
				pusher.Close()
				continue
			}
			if err := pusher.WriteFileAtomic(ctx, remote, newContent, fs.FileMode(0644)); err != nil {
				stragglers = append(stragglers, peerName)
				pusher.Close()
				continue
			}
		}

		if err := pusher.VerifyHealth(ctx); err != nil {
			stragglers = append(stragglers, peerName)
			pusher.Close()
			continue
		}
		pusher.Close()
		touched = append(touched, peerName)
	}

	if len(stragglers) > 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "peers with unfinished pushes (DB not deleted): %s\n", strings.Join(stragglers, ","))
		return fmt.Errorf("group delete incomplete: %d straggler(s)", len(stragglers))
	}

	if err := d.DeleteGroup(ctx, name); err != nil {
		return fmt.Errorf("delete group: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "group %q deleted; affected peers: %s\n", name, strings.Join(touched, ","))
	return nil
}

func newGroupCreateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGroupCreate(cmd, args[0])
		},
	}
}

func newGroupShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show a group's members and the peers that allow it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGroupShow(cmd, args[0])
		},
	}
}

func runGroupCreate(cmd *cobra.Command, name string) error {
	if name == peerfiles.ManagerPrincipal {
		return fmt.Errorf("group %q is reserved", name)
	}

	dbPath, err := cmd.Root().PersistentFlags().GetString("db")
	if err != nil {
		return fmt.Errorf("get db: %w", err)
	}
	dbPath = expandHome(dbPath)

	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	if err := d.CreateGroup(ctx, name); err != nil {
		switch {
		case errors.Is(err, db.ErrGroupExists):
			return fmt.Errorf("group %q already exists", name)
		case errors.Is(err, db.ErrInvalidGroupName):
			return fmt.Errorf("invalid group name %q", name)
		default:
			return fmt.Errorf("create group: %w", err)
		}
	}

	fmt.Fprintf(cmd.OutOrStdout(), "group %q created\n", name)
	return nil
}

func runGroupShow(cmd *cobra.Command, name string) error {
	dbPath, err := cmd.Root().PersistentFlags().GetString("db")
	if err != nil {
		return fmt.Errorf("get db: %w", err)
	}
	dbPath = expandHome(dbPath)

	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	exists, err := d.GroupExists(ctx, name)
	if err != nil {
		return fmt.Errorf("group exists: %w", err)
	}
	if !exists {
		return fmt.Errorf("group %q does not exist", name)
	}

	members, err := d.GetGroupMembers(ctx, name)
	if err != nil {
		return fmt.Errorf("get group members: %w", err)
	}
	allowedBy, err := d.GetGroupAllowedBy(ctx, name)
	if err != nil {
		return fmt.Errorf("get group allowed-by: %w", err)
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "GROUP\t%s\n", name)
	fmt.Fprintf(w, "MEMBERS\t%s\n", joinOrNone(members))
	fmt.Fprintf(w, "ALLOWED BY\t%s\n", joinOrNone(allowedBy))
	return w.Flush()
}

func joinOrNone(xs []string) string {
	if len(xs) == 0 {
		return "(none)"
	}
	return strings.Join(xs, ",")
}

func newGroupAllowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "allow <group>",
		Short: "Allow a group as an incoming-connection principal on a peer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGroupAction(cmd, args[0], true)
		},
	}
	addGroupFlags(cmd)
	return cmd
}

func newGroupDisallowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "disallow <group>",
		Short: "Disallow a group as an incoming-connection principal on a peer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGroupAction(cmd, args[0], false)
		},
	}
	addGroupFlags(cmd)
	return cmd
}

func addGroupFlags(cmd *cobra.Command) {
	cmd.Flags().String("on", "", "peer to update (required)")
	cmd.Flags().String("host", "", "ssh host to connect to (default: same as --on)")
	_ = cmd.MarkFlagRequired("on")
}

func runGroupAction(cmd *cobra.Command, group string, allow bool) error {
	peerName, err := cmd.Flags().GetString("on")
	if err != nil {
		return err
	}
	host, err := cmd.Flags().GetString("host")
	if err != nil {
		return err
	}

	dbPath, err := cmd.Root().PersistentFlags().GetString("db")
	if err != nil {
		return fmt.Errorf("get db: %w", err)
	}
	dataDir, err := cmd.Root().PersistentFlags().GetString("data-dir")
	if err != nil {
		return fmt.Errorf("get data-dir: %w", err)
	}
	dbPath = expandHome(dbPath)
	dataDir = expandHome(dataDir)

	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	peer, err := d.GetPeer(ctx, peerName)
	if err != nil {
		if errors.Is(err, db.ErrPeerNotFound) {
			return fmt.Errorf("peer %q not found", peerName)
		}
		return fmt.Errorf("get peer: %w", err)
	}
	if host == "" {
		host = peer.DialHost()
	}

	current, err := d.GetPeerAllowedGroups(ctx, peerName)
	if err != nil {
		return fmt.Errorf("get allowed groups: %w", err)
	}

	if allow {
		exists, err := d.GroupExists(ctx, group)
		if err != nil {
			return fmt.Errorf("check group %q: %w", group, err)
		}
		if !exists {
			return fmt.Errorf("group %q does not exist (run \"certhold group create %s\" first)", group, group)
		}
		if contains(current, group) {
			fmt.Fprintf(cmd.OutOrStdout(), "group %q already allowed on %s\n", group, peerName)
			return nil
		}
		current = append(current, group)
	} else {
		if !contains(current, group) {
			fmt.Fprintf(cmd.OutOrStdout(), "group %q not currently allowed on %s\n", group, peerName)
			return nil
		}
		current = removeStr(current, group)
	}

	if err := d.SetPeerAllowedGroups(ctx, peerName, current); err != nil {
		return fmt.Errorf("set allowed groups: %w", err)
	}

	peerUnlock := newPeerUnlocker()
	defer peerUnlock.Zero()

	pushOpts := selfPushOptions(dataDir, resolveSelfIdent(ctx, d), peerUnlock.get)
	pushOpts.User = pushUser(peer)
	pusher, err := groupDial(ctx, host, pushOpts)
	if err != nil {
		return fmt.Errorf("ssh dial %s: %w", host, err)
	}
	defer pusher.Close()

	// Inbound trust lives in <home>/.ssh/authorized_keys, isolated per CA —
	// rewrite it in place, no reload.
	caPubBytes, err := ca.LoadPublicKey(filepath.Join(dataDir, "ca"))
	if err != nil {
		return fmt.Errorf("load ca public key: %w", err)
	}
	caPub, _, _, _, err := ssh.ParseAuthorizedKey(caPubBytes)
	if err != nil {
		return fmt.Errorf("parse ca pubkey: %w", err)
	}
	remote := peerAuthorizedKeysRemotePath(peer)
	existing, err := pusher.ReadFile(ctx, remote)
	if err != nil {
		return fmt.Errorf("read %s: %w", remote, err)
	}
	newContent, err := peerfiles.RewritePrincipals(existing, caPub, current)
	if err != nil {
		return fmt.Errorf("rewrite authorized_keys: %w", err)
	}
	if err := pusher.WriteFileAtomic(ctx, remote, newContent, fs.FileMode(0644)); err != nil {
		return fmt.Errorf("write %s: %w", remote, err)
	}
	if err := pusher.VerifyHealth(ctx); err != nil {
		return fmt.Errorf("verify health: %w", err)
	}

	if allow {
		fmt.Fprintf(cmd.OutOrStdout(), "group %q allowed on %s\n", group, peerName)
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "group %q disallowed on %s\n", group, peerName)
	}
	return nil
}

func pushUser(p *db.Peer) string {
	if p.TargetUser != "" {
		return p.TargetUser
	}
	return "root"
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func removeStr(xs []string, v string) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}
