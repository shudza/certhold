package peerfiles

import (
	"fmt"
	"os"
	"path/filepath"
)

func WriteSelfFiles(dir string, p PeerFiles) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	authPrincipals := []byte("manager\n")
	for _, g := range p.AuthPrincipalsRoot {
		authPrincipals = append(authPrincipals, []byte(g+"\n")...)
	}

	krl := p.KRL
	if krl == nil {
		krl = []byte{}
	}

	entries := []struct {
		name string
		mode os.FileMode
		data []byte
	}{
		{"etc/ssh/peer_ed25519", 0600, p.PrivKey},
		{"etc/ssh/peer_ed25519-cert.pub", 0644, p.CertPub},
		{"etc/ssh/ca.pub", 0644, p.CAPub},
		{"etc/ssh/krl", 0644, krl},
		{"etc/ssh/sshd_config.d/certhold.conf", 0644, []byte(sshdConfigContents)},
		{"etc/ssh/auth_principals/root", 0644, authPrincipals},
		{"etc/ssh/ca_known_hosts", 0644, []byte(p.CAKnownHostsEntry + "\n")},
		{"etc/ssh/ssh_config.d/certhold.conf", 0644, []byte(sshConfigContents)},
	}

	for _, e := range entries {
		full := filepath.Join(dir, e.name)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, e.data, e.mode); err != nil {
			return fmt.Errorf("write %s: %w", full, err)
		}
		if err := os.Chmod(full, e.mode); err != nil {
			return fmt.Errorf("chmod %s: %w", full, err)
		}
	}
	return nil
}
