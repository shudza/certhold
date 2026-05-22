// Package peerfiles builds the on-disk file set installed on each peer.
package peerfiles

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"time"
)

type PeerFiles struct {
	Hostname           string
	PrivKey            []byte
	CertPub            []byte
	CAPub              []byte
	KRL                []byte
	AuthPrincipalsRoot []string
	CAKnownHostsEntry  string
}

const sshdConfigContents = `HostKey /etc/ssh/peer_ed25519
HostCertificate /etc/ssh/peer_ed25519-cert.pub
TrustedUserCAKeys /etc/ssh/ca.pub
RevokedKeys /etc/ssh/krl
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
`

const sshConfigContents = `Host *
    CertificateFile /etc/ssh/peer_ed25519-cert.pub
    IdentityFile /etc/ssh/peer_ed25519
    UserKnownHostsFile /etc/ssh/ca_known_hosts
`

func Build(p PeerFiles) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

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
		mode int64
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

	modTime := time.Unix(0, 0).UTC()
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     e.mode,
			Size:     int64(len(e.data)),
			Typeflag: tar.TypeReg,
			Format:   tar.FormatPAX,
			ModTime:  modTime,
			Uid:      0,
			Gid:      0,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(e.data); err != nil {
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
