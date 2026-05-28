package peerfiles

import "fmt"

const (
	LayoutV2      = 2
	CurrentLayout = LayoutV2
)

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

// V2SshClientBlock is the per-instance outbound identity block spliced into
// <home>/.ssh/config. The key namespaces the identity files so multiple certhold
// instances coexist on the same peer.
func V2SshClientBlock(instanceKey string) string {
	return BeginSentinel(instanceKey) + `
Host *
    CertificateFile ~/.ssh/id_ed25519_` + instanceKey + `-cert.pub
    IdentityFile ~/.ssh/id_ed25519_` + instanceKey + `
    UserKnownHostsFile ~/.ssh/known_hosts
` + EndSentinel(instanceKey) + "\n"
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
