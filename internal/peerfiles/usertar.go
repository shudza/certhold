package peerfiles

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type UserPeerFiles struct {
	TargetUser      string
	PrivKey         []byte
	CertPub         []byte
	CAPub           []byte
	Principals      []string
	KnownHostsLines []string
}

const UserSSHClientConfig = `Host *
    CertificateFile ~/.ssh/id_ed25519-cert.pub
    IdentityFile ~/.ssh/id_ed25519
    UserKnownHostsFile ~/.ssh/known_hosts
`

// BuildUser returns a gzip+tar archive containing five entries with paths
// relative to ~user/.ssh/. The install script untars this into that directory.
func BuildUser(p UserPeerFiles) ([]byte, error) {
	authKeys := buildAuthorizedKeysLine(p.CAPub, p.Principals)
	knownHosts := buildKnownHosts(p.KnownHostsLines)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	entries := []struct {
		name string
		mode int64
		data []byte
	}{
		{"id_ed25519", 0600, p.PrivKey},
		{"id_ed25519-cert.pub", 0644, p.CertPub},
		{"authorized_keys", 0644, authKeys},
		{"known_hosts", 0644, knownHosts},
		{"config", 0644, []byte(UserSSHClientConfig)},
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

// WriteUserSelfFiles writes the same five files as BuildUser into
// <dir>/home/<target_user>/.ssh/, mirroring the on-disk layout the admin would
// see after running the user-mode install script.
func WriteUserSelfFiles(dir string, p UserPeerFiles) error {
	if p.TargetUser == "" {
		return fmt.Errorf("target user is empty")
	}
	authKeys := buildAuthorizedKeysLine(p.CAPub, p.Principals)
	knownHosts := buildKnownHosts(p.KnownHostsLines)

	base := filepath.Join(dir, "home", p.TargetUser, ".ssh")
	if err := os.MkdirAll(base, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", base, err)
	}
	entries := []struct {
		name string
		mode os.FileMode
		data []byte
	}{
		{"id_ed25519", 0600, p.PrivKey},
		{"id_ed25519-cert.pub", 0644, p.CertPub},
		{"authorized_keys", 0644, authKeys},
		{"known_hosts", 0644, knownHosts},
		{"config", 0644, []byte(UserSSHClientConfig)},
	}
	for _, e := range entries {
		full := filepath.Join(base, e.name)
		if err := os.WriteFile(full, e.data, e.mode); err != nil {
			return fmt.Errorf("write %s: %w", full, err)
		}
		if err := os.Chmod(full, e.mode); err != nil {
			return fmt.Errorf("chmod %s: %w", full, err)
		}
	}
	return nil
}

// buildAuthorizedKeysLine returns a single newline-terminated cert-authority
// line. The principals list is prefixed with "manager" (deduped).
// The format is documented in PLAN.md ("User level vs root level scoping") and
// matched by authorized.RewritePrincipals — keep this in sync with that regex.
func buildAuthorizedKeysLine(caPub []byte, principals []string) []byte {
	caTrim := strings.TrimRight(string(caPub), "\n")
	all := []string{"manager"}
	seen := map[string]struct{}{"manager": {}}
	for _, p := range principals {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		all = append(all, p)
	}
	line := `cert-authority,principals="` + strings.Join(all, ",") + `" ` + caTrim + "\n"
	return []byte(line)
}

func buildKnownHosts(lines []string) []byte {
	if len(lines) == 0 {
		return []byte{}
	}
	var b strings.Builder
	for _, l := range lines {
		l = strings.TrimRight(l, "\n")
		b.WriteString(l)
		b.WriteString("\n")
	}
	return []byte(b.String())
}
