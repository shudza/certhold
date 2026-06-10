package peerfiles

import "fmt"

// RefreshBundle is the input for the pull-channel refresh artifact. It carries
// public material only: the renewed certificate, the keyed client config, the
// client CLI script, and a manifest describing the bundle.
type RefreshBundle struct {
	InstanceKey, PeerName, CLIVersion string
	CertPub, CLIScript                []byte
	Hosts                             []HostEntry
	FleetRev                          int64
	CertSerial                        uint64
}

// BuildRefreshBundle returns a reproducible gzip+tar archive for the pull
// channel. It never includes private material (no private key, no
// ca_authorized_keys).
func BuildRefreshBundle(p RefreshBundle) ([]byte, error) {
	manifest := fmt.Sprintf("PEER_NAME=%s\nINSTANCE_KEY=%s\nFLEET_REV=%d\nCERT_SERIAL=%d\nCLI_VERSION=%s\n",
		p.PeerName, p.InstanceKey, p.FleetRev, p.CertSerial, p.CLIVersion)
	return buildArchive([]userFileEntry{
		{V2CertFileName(p.InstanceKey), 0644, p.CertPub},
		{"config", 0644, []byte(V2SshClientBlockWithHosts(p.InstanceKey, p.Hosts))},
		{"certhold-cli", 0755, p.CLIScript},
		{"manifest", 0644, []byte(manifest)},
	})
}
