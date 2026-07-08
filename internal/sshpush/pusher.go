package sshpush

import (
	"context"
	"io/fs"

	"golang.org/x/crypto/ssh"

	"github.com/shudza/certhold/internal/peerfiles"
)

type Pusher interface {
	WriteFileAtomic(ctx context.Context, remotePath string, content []byte, mode fs.FileMode) error
	ReadFile(ctx context.Context, remotePath string) ([]byte, error)
	SpliceConfigBlock(ctx context.Context, configPath string, instanceKey string, block string) error
	ClearPeer(ctx context.Context, paths peerfiles.RemotePaths, instanceKey string, caPubKeys []ssh.PublicKey) error
	ReloadSSHD(ctx context.Context) error
	VerifyHealth(ctx context.Context) error
	Close() error
}
