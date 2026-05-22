// Package krl builds OpenSSH Key Revocation Lists by shelling out to
// ssh-keygen -k. The KRL is a binary file consumed by sshd's
// RevokedKeys directive on each peer.
package krl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ErrSshKeygenMissing is returned by Build when ssh-keygen cannot be
// located on PATH.
var ErrSshKeygenMissing = errors.New("krl: ssh-keygen not found on PATH")

// Build generates a KRL covering serials, signed against the CA public
// key at caPubKeyPath. An empty serials slice produces a valid, empty
// KRL.
func Build(ctx context.Context, caPubKeyPath string, serials []uint64) ([]byte, error) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		return nil, ErrSshKeygenMissing
	}

	specFile, err := os.CreateTemp("", "krl-spec-*.txt")
	if err != nil {
		return nil, fmt.Errorf("create spec tempfile: %w", err)
	}
	specPath := specFile.Name()
	defer os.Remove(specPath)

	var buf bytes.Buffer
	for _, s := range serials {
		fmt.Fprintf(&buf, "serial: 0x%x\n", s)
	}
	if _, err := specFile.Write(buf.Bytes()); err != nil {
		specFile.Close()
		return nil, fmt.Errorf("write spec: %w", err)
	}
	if err := specFile.Close(); err != nil {
		return nil, fmt.Errorf("close spec: %w", err)
	}

	outFile, err := os.CreateTemp("", "krl-out-*.bin")
	if err != nil {
		return nil, fmt.Errorf("create out tempfile: %w", err)
	}
	outPath := outFile.Name()
	if err := outFile.Close(); err != nil {
		os.Remove(outPath)
		return nil, fmt.Errorf("close out tempfile: %w", err)
	}
	defer os.Remove(outPath)

	cmd := exec.CommandContext(ctx, "ssh-keygen", "-k", "-f", outPath, "-s", caPubKeyPath, specPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ssh-keygen -k: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("read krl output: %w", err)
	}
	return data, nil
}
