package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	flagTrustNewHostKeys = "trust-new-host-keys"
	envTrustNewHostKeys  = "CERTHOLD_TRUST_NEW_HOST_KEYS"
)

// hostKeyConfirm decides whether an unknown peer host key should be accepted
// (TOFU). When autoAccept is set it returns true immediately without touching
// in/out (used for --trust-new-host-keys / CERTHOLD_TRUST_NEW_HOST_KEYS=1).
// Otherwise it prints an SSH-style block to out and reads visible lines from in,
// accepting only "yes"; "no"/empty/EOF reject, and any other input re-prompts.
func hostKeyConfirm(in io.Reader, out io.Writer, host, fingerprint, keyType string, autoAccept bool) (bool, error) {
	if autoAccept {
		return true, nil
	}
	fmt.Fprintf(out, "The authenticity of host %s can't be established.\n", host)
	fmt.Fprintf(out, "%s key fingerprint is %s.\n", keyType, fingerprint)
	r := bufio.NewReader(in)
	for {
		fmt.Fprint(out, "Are you sure you want to continue connecting (yes/no)? ")
		line, err := r.ReadString('\n')
		ans := strings.TrimSpace(line)
		switch ans {
		case "yes":
			return true, nil
		case "no", "":
			return false, nil
		default:
			if err != nil {
				return false, nil
			}
			fmt.Fprint(out, "Please type 'yes' or 'no': ")
		}
	}
}

// newHostKeyConfirm returns an ops.Deps.HostKeyConfirm hook. When autoAccept is
// set the hook short-circuits to accept without prompting; otherwise it prompts
// on /dev/tty, failing closed (reject) if no controlling terminal is available
// so non-interactive runs never block.
func newHostKeyConfirm(autoAccept bool) func(host, fingerprint, keyType string) (bool, error) {
	return func(host, fingerprint, keyType string) (bool, error) {
		if autoAccept {
			return true, nil
		}
		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			return false, nil
		}
		defer tty.Close()
		return hostKeyConfirm(tty, tty, host, fingerprint, keyType, false)
	}
}

// trustNewHostKeys resolves the auto-accept decision from the --trust-new-host-keys
// flag or the CERTHOLD_TRUST_NEW_HOST_KEYS env escape hatch.
func trustNewHostKeys(flag bool) bool {
	if flag {
		return true
	}
	return os.Getenv(envTrustNewHostKeys) == "1"
}
