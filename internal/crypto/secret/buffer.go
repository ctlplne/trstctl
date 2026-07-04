// SPDX-License-Identifier: MPL-2.0

package secret

import (
	"errors"
	"runtime"
	"sync"
)

// ErrInvalidSize is returned by New when the requested size is not positive.
var ErrInvalidSize = errors.New("secret: size must be positive")

// Buffer holds secret material in locked, non-dumpable, zeroizable memory. The
// zero value is not usable; create buffers with New or NewFrom. Destroy is safe
// to call multiple times and from multiple goroutines; callers must not use the
// slice returned by Bytes after Destroy.
type Buffer struct {
	mu     sync.Mutex
	region []byte // full page-rounded backing region, released by free
	data   []byte // user-facing view into region (region[:size])
	freed  bool
}

// New allocates a zeroed Buffer of the given size in locked, non-dumpable
// memory.
func New(size int) (*Buffer, error) {
	if size <= 0 {
		return nil, ErrInvalidSize
	}
	region, err := alloc(size)
	if err != nil {
		return nil, err
	}
	return &Buffer{region: region, data: region[:size:size]}, nil
}

// NewFrom copies src into a new Buffer. src is not modified; callers that want
// the source wiped should Wipe it themselves once the Buffer is created.
func NewFrom(src []byte) (*Buffer, error) {
	b, err := New(len(src))
	if err != nil {
		return nil, err
	}
	copy(b.data, src)
	return b, nil
}

// Bytes returns the secret bytes for use. The slice is valid only until Destroy
// and must not be retained afterward. It is nil once the buffer is destroyed.
func (b *Buffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data
}

// Len returns the size of the secret in bytes (0 once destroyed).
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.data)
}

// Destroy zeroizes the buffer and releases its backing memory. It is idempotent.
func (b *Buffer) Destroy() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.freed {
		return
	}
	Wipe(b.region)
	_ = free(b.region)
	b.region = nil
	b.data = nil
	b.freed = true
}

// Wipe sets every byte of b to zero. runtime.KeepAlive prevents the compiler
// from treating the writes as dead and eliminating them.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
