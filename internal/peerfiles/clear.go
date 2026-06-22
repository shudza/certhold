package peerfiles

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

// StripBlock removes the keyed sentinel range for instanceKey from an ssh config
// body, the inverse of the install-script splice. It matches any version suffix
// (the same `( v[0-9]+)?` shape the enroll-script sed and SpliceConfigBlock use),
// so legacy blocks are removed too. With no matching block present the input is
// returned unchanged.
func StripBlock(existing []byte, instanceKey string) []byte {
	key := regexp.QuoteMeta(instanceKey)
	re := regexp.MustCompile(fmt.Sprintf(
		`(?m)^# BEGIN certhold %s( v[0-9]+)?$\n(?s:.*?)^# END certhold %s( v[0-9]+)?$\n?`,
		key, key))
	return re.ReplaceAll(existing, nil)
}

// StripCALine removes the cert-authority line whose key matches caPubKey from an
// authorized_keys body, reusing the matching logic in authorized.go. Every other
// line — including a cert-authority line for a different CA — is preserved
// verbatim. With no matching line present the input is returned unchanged.
func StripCALine(existing []byte, caPubKey ssh.PublicKey) []byte {
	caMarshalled := caPubKey.Marshal()

	var out bytes.Buffer
	scanner := newLineScanner(existing)
	for scanner.next() {
		line := scanner.line()
		raw := strings.TrimRight(string(line), "\r")
		trim := strings.TrimSpace(raw)
		if trim == "" || strings.HasPrefix(trim, "#") {
			writeLine(&out, line)
			continue
		}
		matched, err := lineMatchesCA(trim, caMarshalled)
		if err != nil || !matched {
			writeLine(&out, line)
			continue
		}
	}
	return out.Bytes()
}
