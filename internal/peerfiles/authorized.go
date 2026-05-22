package peerfiles

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

var (
	ErrNoMatchingLine = errors.New("authorized_keys: no cert-authority line matches CA")
	ErrMalformedLine  = errors.New("authorized_keys: cert-authority line malformed (missing principals=)")
)

// RewritePrincipals scans `existing` for an authorized_keys line whose options
// include `cert-authority`, whose key payload matches caPubKey, and rewrites
// its `principals="..."` substring. "manager" is always prepended (deduped).
// Other lines are preserved verbatim.
func RewritePrincipals(existing []byte, caPubKey ssh.PublicKey, principals []string) ([]byte, error) {
	caMarshalled := caPubKey.Marshal()
	all := dedupPrincipals(principals)
	newPrincipals := `principals="` + strings.Join(all, ",") + `"`

	var out bytes.Buffer
	scanner := newLineScanner(existing)
	found := false
	for scanner.next() {
		line := scanner.line()
		raw := strings.TrimRight(string(line), "\r")
		trim := strings.TrimSpace(raw)
		if trim == "" || strings.HasPrefix(trim, "#") {
			writeLine(&out, line)
			continue
		}
		matched, err := lineMatchesCA(trim, caMarshalled)
		if err != nil {
			writeLine(&out, line)
			continue
		}
		if !matched {
			writeLine(&out, line)
			continue
		}
		rewritten, err := rewriteLineOptions(raw, newPrincipals)
		if err != nil {
			return nil, err
		}
		out.WriteString(rewritten)
		out.WriteByte('\n')
		found = true
	}
	if !found {
		return nil, ErrNoMatchingLine
	}
	return out.Bytes(), nil
}

func dedupPrincipals(principals []string) []string {
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
	return all
}

// lineMatchesCA parses an authorized_keys line and reports whether it has the
// cert-authority option AND its key bytes match caMarshalled.
func lineMatchesCA(line string, caMarshalled []byte) (bool, error) {
	pk, _, options, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return false, err
	}
	hasCA := false
	for _, o := range options {
		base := o
		if eq := strings.IndexByte(o, '='); eq >= 0 {
			base = o[:eq]
		}
		if base == "cert-authority" {
			hasCA = true
			break
		}
	}
	if !hasCA {
		return false, nil
	}
	return bytes.Equal(pk.Marshal(), caMarshalled), nil
}

// rewriteLineOptions replaces the principals="..." substring on a cert-authority
// line. The format of options is: comma-separated, with quoted values allowed.
// We do a focused regex-free splice: find `principals="` then the matching
// closing `"`, swap the whole `principals="..."` token.
func rewriteLineOptions(line, newPrincipals string) (string, error) {
	idx := strings.Index(line, `principals="`)
	if idx < 0 {
		return "", fmt.Errorf("%w: %q", ErrMalformedLine, line)
	}
	rest := line[idx+len(`principals="`):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return "", fmt.Errorf("%w: %q", ErrMalformedLine, line)
	}
	return line[:idx] + newPrincipals + rest[end+1:], nil
}

type lineScanner struct {
	buf []byte
	pos int
	cur []byte
}

func newLineScanner(buf []byte) *lineScanner { return &lineScanner{buf: buf} }

func (s *lineScanner) next() bool {
	if s.pos >= len(s.buf) {
		return false
	}
	start := s.pos
	for s.pos < len(s.buf) && s.buf[s.pos] != '\n' {
		s.pos++
	}
	s.cur = s.buf[start:s.pos]
	if s.pos < len(s.buf) {
		s.pos++
	}
	return true
}

func (s *lineScanner) line() []byte { return s.cur }

func writeLine(out *bytes.Buffer, line []byte) {
	out.Write(line)
	out.WriteByte('\n')
}
