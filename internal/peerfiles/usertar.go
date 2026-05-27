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
	// Layout selects the on-disk file set. Zero means LayoutV1 (legacy
	// user-mode). LayoutV2 namespaces the identity files by InstanceKey and
	// drops the whole-file authorized_keys from the install tarball.
	Layout      int
	InstanceKey string
}

const UserSSHClientConfig = `Host *
    CertificateFile ~/.ssh/id_ed25519-cert.pub
    IdentityFile ~/.ssh/id_ed25519
    UserKnownHostsFile ~/.ssh/known_hosts
`

func (p UserPeerFiles) layout() int {
	if p.Layout == 0 {
		return LayoutV1
	}
	return p.Layout
}

// userFileEntry is one file destined for ~user/.ssh/.
type userFileEntry struct {
	name string
	mode int64
	data []byte
}

// userFileEntries returns the on-disk file set for the peer's layout. v1 ships
// the historical five entries (including a whole authorized_keys). v2 ships only
// the namespaced identity files, known_hosts (TOFU), and the keyed client config;
// the install script appends the cert-authority line idempotently.
func userFileEntries(p UserPeerFiles) []userFileEntry {
	if p.layout() >= LayoutV2 {
		return []userFileEntry{
			{V2KeyFileName(p.InstanceKey), 0600, p.PrivKey},
			{V2CertFileName(p.InstanceKey), 0644, p.CertPub},
			{"known_hosts", 0644, buildKnownHosts(p.KnownHostsLines)},
			{"config", 0644, []byte(V2SshClientBlock(p.InstanceKey))},
			// The full cert-authority line for this instance's CA. The install
			// script appends it to authorized_keys idempotently (grep-guarded)
			// rather than clobbering the file, so multiple instances coexist.
			{"ca_authorized_keys", 0644, buildAuthorizedKeysLine(p.CAPub, p.Principals)},
		}
	}
	return []userFileEntry{
		{"id_ed25519", 0600, p.PrivKey},
		{"id_ed25519-cert.pub", 0644, p.CertPub},
		{"authorized_keys", 0644, buildAuthorizedKeysLine(p.CAPub, p.Principals)},
		{"known_hosts", 0644, buildKnownHosts(p.KnownHostsLines)},
		{"config", 0644, []byte(UserSSHClientConfig)},
	}
}

// BuildUser returns a gzip+tar archive whose entries have paths relative to
// ~user/.ssh/. The install script untars this into that directory.
func BuildUser(p UserPeerFiles) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	entries := userFileEntries(p)

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
// <dir>/<HomeOf(target_user)>/.ssh/ (e.g. <dir>/root/.ssh/ for root,
// <dir>/home/alice/.ssh/ for alice). The leading slash from HomeOf is stripped
// so the result mirrors the on-disk layout the admin would see after running
// the user-mode install script: `cp -r <dir>/. /` copies straight into place.
func WriteUserSelfFiles(dir string, p UserPeerFiles) error {
	if p.TargetUser == "" {
		return fmt.Errorf("target user is empty")
	}

	homeRel := strings.TrimPrefix(HomeOf(p.TargetUser), "/")
	base := filepath.Join(dir, homeRel, ".ssh")
	if err := os.MkdirAll(base, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", base, err)
	}
	var entries []userFileEntry
	for _, e := range userFileEntries(p) {
		if e.name == "ca_authorized_keys" {
			continue
		}
		entries = append(entries, e)
	}
	if p.layout() >= LayoutV2 {
		entries = append(entries, userFileEntry{"authorized_keys", 0644, buildAuthorizedKeysLine(p.CAPub, p.Principals)})
	}
	for _, e := range entries {
		full := filepath.Join(base, e.name)
		mode := os.FileMode(e.mode)
		if err := os.WriteFile(full, e.data, mode); err != nil {
			return fmt.Errorf("write %s: %w", full, err)
		}
		if err := os.Chmod(full, mode); err != nil {
			return fmt.Errorf("chmod %s: %w", full, err)
		}
	}
	return nil
}

// AuthorizedKeysLine is the exported form of buildAuthorizedKeysLine for callers
// outside this package (e.g. the install script) that need the exact line the
// peer's authorized_keys should carry for this CA.
func AuthorizedKeysLine(caPub []byte, principals []string) []byte {
	return buildAuthorizedKeysLine(caPub, principals)
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
