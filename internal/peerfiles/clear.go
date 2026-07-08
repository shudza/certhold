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

// StripCALine removes every cert-authority line whose key matches one of
// caPubKeys from an authorized_keys body, reusing the matching logic in
// authorized.go. Multiple keys let revoke strip this instance's active AND
// archived (pre-rekey) CA lines in one pass. Every other line — including a
// cert-authority line for a different instance's CA — is preserved verbatim.
// With no matching line present the input is returned unchanged.
func StripCALine(existing []byte, caPubKeys ...ssh.PublicKey) []byte {
	marshalled := make([][]byte, len(caPubKeys))
	for i, k := range caPubKeys {
		marshalled[i] = k.Marshal()
	}

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
		mine := false
		for _, m := range marshalled {
			matched, err := lineMatchesCA(trim, m)
			if err == nil && matched {
				mine = true
				break
			}
		}
		if !mine {
			writeLine(&out, line)
		}
	}
	return out.Bytes()
}
