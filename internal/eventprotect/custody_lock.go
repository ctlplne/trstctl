// SPDX-License-Identifier: BUSL-1.1

package eventprotect

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type custodyFenceKey struct{}
type custodyFence struct {
	authority *FileAuthority
	tenantID  string
	active    atomic.Bool
	borrow    sync.Mutex
}

// WithCustodyFence holds independent custody without retaining key bytes over
// the caller's source/SQL verification. Nested key reads borrow only this live
// authority/tenant grant; concurrent or escaped borrowers refuse.
func (a *FileAuthority) WithCustodyFence(ctx context.Context, ref KeyRef, visit func(context.Context) error) error {
	if visit == nil {
		return ErrContext
	}
	return a.withLock(ctx, ref, func(ctx context.Context, _ KeyRef) error { return visit(ctx) })
}

// The filename is non-secret tenant routing metadata. Never unlink a lock
// file: another process can still hold its inode while a replacement is opened.
func (a *FileAuthority) lockCustodyFile(ctx context.Context, tenantID string) (func(), error) {
	file, err := a.root.OpenFile(".tenant-"+tenantID+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, ErrKey
	}
	for {
		if err := ctx.Err(); err != nil {
			_ = file.Close()
			return nil, err
		}
		locked, err := tryCustodyFileLock(file)
		if err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("eventprotect: independent custody lock: %w", err)
		}
		if locked {
			return func() { _ = unlockCustodyFile(file); _ = file.Close() }, nil
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = file.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
