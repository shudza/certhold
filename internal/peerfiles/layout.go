package peerfiles

import "fmt"

const (
	LayoutV1      = 1
	CurrentLayout = LayoutV1
)

func BeginSentinel(layout int) string {
	return fmt.Sprintf("# BEGIN certhold v%d", layout)
}

func EndSentinel(layout int) string {
	return fmt.Sprintf("# END certhold v%d", layout)
}

func SshdBlock(layout int) string {
	return BeginSentinel(layout) + `
HostKey /etc/ssh/peer_ed25519
HostCertificate /etc/ssh/peer_ed25519-cert.pub
TrustedUserCAKeys /etc/ssh/ca.pub
RevokedKeys /etc/ssh/krl
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
` + EndSentinel(layout) + "\n"
}

func SshClientBlock(layout int) string {
	return BeginSentinel(layout) + `
Host *
    CertificateFile /etc/ssh/peer_ed25519-cert.pub
    IdentityFile /etc/ssh/peer_ed25519
    UserKnownHostsFile /etc/ssh/ca_known_hosts
` + EndSentinel(layout) + "\n"
}

// RemotePaths is the path-dispatch seam for the on-disk peer layout. PR1 returns
// today's paths for v1; PR2 forks here on layout/instanceKey without changing the
// caller signatures.
type RemotePaths struct {
	Cert           string
	AuthorizedKeys string
	CAPub          string
	KRL            string
	KnownHosts     string
	ConfigTarget   string
}

func PathsFor(layout int, mode, targetUser, instanceKey string) RemotePaths {
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
