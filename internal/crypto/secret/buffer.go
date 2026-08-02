// SPDX-License-Identifier: MPL-2.0

package secret

import (
	"errors"
	"runtime"
	"sync"
)

// ErrInvalidSize is returned by New when the requested size is not positive.
var ErrInvalidSize = errors.New("secret: size must be positive")

// ErrDestroyed is returned by Use when the buffer has already been destroyed.
var ErrDestroyed = errors.New("secret: buffer has been destroyed")

// Buffer holds secret material in locked, non-dumpable, zeroizable memory. The
// zero value is not usable; create buffers with New or NewFrom. Destroy is safe
// to call multiple times and from multiple goroutines; callers must not use the
// slice returned by Bytes after Destroy.
//
// Lifetime (AN-8): Destroy wipes AND releases the backing region — on Linux that
// ends in munmap, so a slice handed out by Bytes becomes a dangling pointer the
// instant Destroy returns. Any caller that may race a Destroy must read the
// secret inside Use, which holds the read side of mu for the whole borrow and
// therefore makes Destroy wait rather than unmap memory out from under it.
type Buffer struct {
	mu     sync.RWMutex
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
//
// Bytes releases mu before the caller reads the slice, so it is safe ONLY when
// no other goroutine can Destroy this buffer during the read. When a concurrent
// Destroy is possible — every key custodied by the signer, which serves both
// Sign and DestroyKey — use Use instead.
func (b *Buffer) Bytes() []byte {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.data
}

// Use borrows the secret bytes for the duration of fn while holding the read
// side of mu, so the region cannot be wiped or released mid-read: a concurrent
// Destroy blocks until every in-flight Use has returned. If the buffer is
// already destroyed, fn is not called and ErrDestroyed is returned.
//
// fn must not retain the slice after it returns, and must not call Destroy or
// Use on the same Buffer: sync.RWMutex is not reentrant and does not starve
// writers, so a nested borrow behind a queued Destroy deadlocks.
func (b *Buffer) Use(fn func([]byte) error) error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.freed {
		return ErrDestroyed
	}
	err := fn(b.data)
	runtime.KeepAlive(b)
	return err
}

// Len returns the size of the secret in bytes (0 once destroyed).
func (b *Buffer) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.data)
}

// Destroy zeroizes the buffer and releases its backing memory. It is idempotent.
// It takes the write side of mu, so it BLOCKS until every in-flight Use borrow
// has returned; that wait is what makes "the region is gone" a true postcondition
// instead of a use-after-free for whoever is still reading it. The wait is bounded
// by one in-process private-key operation — there is no I/O inside a borrow.
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
