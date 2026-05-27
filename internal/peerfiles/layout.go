package peerfiles

import "fmt"

const (
	LayoutV1      = 1
	LayoutV2      = 2
	CurrentLayout = LayoutV2
)

// BeginSentinel returns the begin marker for a layout's spliced block. v1 keeps
// the keyless form so already-deployed peers' version-agnostic sed still matches.
// v2 embeds the per-instance key before the version so the key is matched while
// the version suffix stays optional in the sed pattern.
func BeginSentinel(layout int, instanceKey string) string {
	if layout >= LayoutV2 {
		return fmt.Sprintf("# BEGIN certhold %s v%d", instanceKey, layout)
	}
	return fmt.Sprintf("# BEGIN certhold v%d", layout)
}

func EndSentinel(layout int, instanceKey string) string {
	if layout >= LayoutV2 {
		return fmt.Sprintf("# END certhold %s v%d", instanceKey, layout)
	}
	return fmt.Sprintf("# END certhold v%d", layout)
}

func SshdBlock(layout int) string {
	return BeginSentinel(layout, "") + `
HostKey /etc/ssh/peer_ed25519
HostCertificate /etc/ssh/peer_ed25519-cert.pub
TrustedUserCAKeys /etc/ssh/ca.pub
RevokedKeys /etc/ssh/krl
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
` + EndSentinel(layout, "") + "\n"
}

func SshClientBlock(layout int) string {
	return BeginSentinel(layout, "") + `
Host *
    CertificateFile /etc/ssh/peer_ed25519-cert.pub
    IdentityFile /etc/ssh/peer_ed25519
    UserKnownHostsFile /etc/ssh/ca_known_hosts
` + EndSentinel(layout, "") + "\n"
}

// V2SshClientBlock is the per-instance outbound identity block spliced into
// <home>/.ssh/config. The key namespaces the identity files so multiple certhold
// instances coexist on the same peer.
func V2SshClientBlock(instanceKey string) string {
	return BeginSentinel(LayoutV2, instanceKey) + `
Host *
    CertificateFile ~/.ssh/id_ed25519_` + instanceKey + `-cert.pub
    IdentityFile ~/.ssh/id_ed25519_` + instanceKey + `
    UserKnownHostsFile ~/.ssh/known_hosts
` + EndSentinel(LayoutV2, instanceKey) + "\n"
}

// RemotePaths is the path-dispatch seam for the on-disk peer layout. v1 returns
// today's paths; v2 (both modes) returns namespaced user-style paths under
// <HomeOf(targetUser)>/.ssh/.
type RemotePaths struct {
	Cert           string
	AuthorizedKeys string
	CAPub          string
	KRL            string
	KnownHosts     string
	ConfigTarget   string
}

func PathsFor(layout int, mode, targetUser, instanceKey string) RemotePaths {
	if layout >= LayoutV2 {
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
	if mode == "user" {
		user := targetUser
		if user == "" {
			user = "root"
		}
		base := HomeOf(user) + "/.ssh"
		return RemotePaths{
			Cert:           base + "/id_ed25519-cert.pub",
			AuthorizedKeys: base + "/authorized_keys",
			CAPub:          base + "/ca.pub",
			KRL:            base + "/krl",
			KnownHosts:     base + "/known_hosts",
			ConfigTarget:   base + "/config",
		}
	}
	return RemotePaths{
		Cert:           "/etc/ssh/peer_ed25519-cert.pub",
		AuthorizedKeys: "/etc/ssh/auth_principals/root",
		CAPub:          "/etc/ssh/ca.pub",
		KRL:            "/etc/ssh/krl",
		KnownHosts:     "/etc/ssh/ca_known_hosts",
		ConfigTarget:   "/etc/ssh/sshd_config",
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
