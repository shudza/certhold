package sshpush

import (
	"context"
	"io/fs"
)

type Pusher interface {
	WriteFileAtomic(ctx context.Context, remotePath string, content []byte, mode fs.FileMode) error
	ReadFile(ctx context.Context, remotePath string) ([]byte, error)
	ReloadSSHD(ctx context.Context) error
	VerifyHealth(ctx context.Context) error
	Close() error
}
