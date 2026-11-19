// SPDX-License-Identifier: BUSL-1.1

package safefile

import (
	"context"
	"errors"
	"io"
	"math"
	"os"
)

var (
	ErrNotRegular = errors.New("path must name a regular file")
	ErrFileLimit  = errors.New("regular file exceeds the read limit")
)

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
	if !info.Mode().IsRegular() {
		return nil, ErrNotRegular
	}
	file, err := root.OpenFile(name, readOnlyNonblocking, 0)
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
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx: ctx, reader: file}, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, ErrFileLimit
	}
	if err := ctx.Err(); err != nil {
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
