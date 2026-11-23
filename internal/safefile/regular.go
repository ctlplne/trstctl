// SPDX-License-Identifier: BUSL-1.1

package safefile

import (
	"context"
	"errors"
	"io"
	"math"
	"os"

	"trstctl.com/trstctl/internal/crypto/secret"
)

var (
	ErrNotRegular = errors.New("path must name a regular file")
	ErrFileLimit  = errors.New("regular file exceeds the read limit")
)

// OpenDirectory refuses special files before and after a nonblocking open.
// This is needed when expanding a tenant-supplied glob: a path that used to be
// a directory could be swapped for a FIFO between the check and open.
func OpenDirectory(ctx context.Context, root *os.Root, name string) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := root.Stat(name)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, ErrNotRegular
	}
	dir, err := root.OpenFile(name, readOnlyNonblockingNoFollow, 0)
	if err != nil {
		return nil, err
	}
	info, err = dir.Stat()
	if err != nil || !info.IsDir() {
		_ = dir.Close()
		if err != nil {
			return nil, err
		}
		return nil, ErrNotRegular
	}
	return dir, nil
}

// ReadRegularFile opens a filesystem-relative name within root and reads at
// most maxBytes. It checks the open descriptor, so replacement between the
// preliminary mode check and the open cannot turn this into a device read.
func ReadRegularFile(ctx context.Context, root *os.Root, name string, maxBytes int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if maxBytes <= 0 || maxBytes == math.MaxInt64 {
		return nil, ErrFileLimit
	}
	info, err := root.Stat(name)
	if err != nil {
		return nil, err
	}
	return readRegularOpened(ctx, info, func() (*os.File, error) {
		return root.OpenFile(name, readOnlyNonblocking, 0)
	}, maxBytes)
}

// ReadRegularFileNoFollow adds a final-component no-follow check. os.Root
// already confines every intermediate path component to root; this refuses a
// selected file replaced by a symlink between enumeration and opening.
func ReadRegularFileNoFollow(ctx context.Context, root *os.Root, name string, maxBytes int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if maxBytes <= 0 || maxBytes == math.MaxInt64 {
		return nil, ErrFileLimit
	}
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	return readRegularOpened(ctx, info, func() (*os.File, error) {
		return root.OpenFile(name, readOnlyNonblockingNoFollow, 0)
	}, maxBytes)
}

// ReadRegularPath is for an agent's own operator-configured path, where a
// symlink to another host directory is legitimate. The opened descriptor is
// still checked and read with O_NONBLOCK and a strict size limit.
func ReadRegularPath(ctx context.Context, path string, maxBytes int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if maxBytes <= 0 || maxBytes == math.MaxInt64 {
		return nil, ErrFileLimit
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	return readRegularOpened(ctx, info, func() (*os.File, error) {
		return os.OpenFile(path, readOnlyNonblocking, 0) // #nosec G304 -- agent-owned path; the opened descriptor is regular/size checked before reading
	}, maxBytes)
}

func readRegularOpened(ctx context.Context, info os.FileInfo, open func() (*os.File, error), maxBytes int64) ([]byte, error) {
	if !info.Mode().IsRegular() {
		return nil, ErrNotRegular
	}
	file, err := open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err = file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, ErrNotRegular
	}
	if info.Size() > maxBytes {
		return nil, ErrFileLimit
	}
	if info.Size() >= int64(^uint(0)>>1) {
		return nil, ErrFileLimit
	}
	// One owned allocation avoids io.ReadAll growth copies that a caller
	// cannot wipe after hashing a credential file.
	data, err := secret.ReadBounded(io.LimitReader(contextReader{ctx: ctx, reader: file}, info.Size()+1), int(info.Size()+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > info.Size() || int64(len(data)) > maxBytes {
		secret.Wipe(data)
		return nil, ErrFileLimit
	}
	if err := ctx.Err(); err != nil {
		secret.Wipe(data)
		return nil, err
	}
	return data, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
