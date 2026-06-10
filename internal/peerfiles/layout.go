package peerfiles

import (
	"fmt"
	"strings"
)

const LayoutV2 = 2

// BeginSentinel returns the begin marker for an instance's spliced block. The
// per-instance key is embedded before the version so the key is matched while
// the version suffix stays optional in the install script's sed pattern,
// letting multiple certhold instances coexist on the same peer.
func BeginSentinel(instanceKey string) string {
	return fmt.Sprintf("# BEGIN certhold %s v%d", instanceKey, LayoutV2)
}

func EndSentinel(instanceKey string) string {
	return fmt.Sprintf("# END certhold %s v%d", instanceKey, LayoutV2)
}

// HostEntry is one per-peer ssh alias emitted as a `Host <Name>` stanza ahead
// of the catch-all `Host *` stanza in the keyed client block.
type HostEntry struct {
	Name, Address, User string
}

// V2SshClientBlock is the per-instance outbound identity block spliced into
// <home>/.ssh/config. The key namespaces the identity files so multiple certhold
// instances coexist on the same peer.
func V2SshClientBlock(instanceKey string) string {
	return V2SshClientBlockWithHosts(instanceKey, nil)
}

// V2SshClientBlockWithHosts is V2SshClientBlock with per-peer Host alias
// stanzas emitted before the `Host *` stanza, inside the keyed sentinel range
// so re-enrollment replaces them too. Entries with both Address and User empty
// are skipped.
func V2SshClientBlockWithHosts(instanceKey string, hosts []HostEntry) string {
	var b strings.Builder
	b.WriteString(BeginSentinel(instanceKey))
	b.WriteString(`
# This block is managed by certhold -- auto-generated, do not edit by hand.
# It makes the local ssh client present the certhold-issued certificate
# (CertificateFile + IdentityFile below) on every outbound ssh connection.
# The instance key in the sentinel lines namespaces this block so multiple
# certhold installs can coexist on the same host without clobbering each other.
# To refresh, re-run the enroll one-liner; it idempotently replaces this range.
`)
	for _, h := range hosts {
		if h.Address == "" && h.User == "" {
			continue
		}
		b.WriteString("Host " + h.Name + "\n")
		if h.Address != "" {
			b.WriteString("    HostName " + h.Address + "\n")
		}
		if h.User != "" {
			b.WriteString("    User " + h.User + "\n")
		}
	}
	b.WriteString(`Host *
    CertificateFile ~/.ssh/id_ed25519_` + instanceKey + `-cert.pub
    IdentityFile ~/.ssh/id_ed25519_` + instanceKey + `
    UserKnownHostsFile ~/.ssh/known_hosts
` + EndSentinel(instanceKey) + "\n")
	return b.String()
}

// RemotePaths is the on-disk peer layout: namespaced user-style paths under
// <HomeOf(targetUser)>/.ssh/.
type RemotePaths struct {
	Cert           string
	AuthorizedKeys string
	CAPub          string
	KRL            string
	KnownHosts     string
	ConfigTarget   string
}

// PathsFor returns the remote paths for an instance's files under the target
// user's ~/.ssh/. An empty targetUser resolves to root.
func PathsFor(targetUser, instanceKey string) RemotePaths {
	user := targetUser
	if user == "" {
		user = "root"
	}
	base := HomeOf(user) + "/.ssh"
	return RemotePaths{
		Cert:           base + "/id_ed25519_" + instanceKey + "-cert.pub",
		AuthorizedKeys: base + "/authorized_keys",
		KnownHosts:     base + "/known_hosts",
		ConfigTarget:   base + "/config",
	}
}

// V2KeyFileName is the namespaced private key filename for a v2 instance.
func V2KeyFileName(instanceKey string) string {
	return "id_ed25519_" + instanceKey
}

// V2CertFileName is the namespaced certificate filename for a v2 instance.
func V2CertFileName(instanceKey string) string {
	return "id_ed25519_" + instanceKey + "-cert.pub"
}
