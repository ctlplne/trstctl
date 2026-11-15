// SPDX-License-Identifier: BUSL-1.1

package objectstore

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// RemoveAll deletes objects for good (A206-L2, A206L2-L1). On a store that
// keeps versions (S3 versioning or Object Lock) a plain delete only hides an
// object's data behind a delete marker, so every version the store lists is
// deleted, the data before the markers earlier plain deletes left. A store
// that lists no versions has its current object deleted. Every object's
// Object Lock is read first: if a lock protects any version of any of them,
// nothing is deleted and the error (*ErrLocked) says until when, so a set of
// objects that belong together (a recording's chunks and manifest) is never
// left half removed. A missing object is not an error.
func RemoveAll(ctx context.Context, store Store, names ...string) error {
	versioned, _ := store.(Versioned)
	plans := make([][]Version, len(names))
	var locked *ErrLocked
	now := time.Now()
	for i, name := range names {
		var err error
		if versioned != nil {
			plans[i], err = versioned.Versions(ctx, name)
			switch {
			case errors.Is(err, ErrVersionsUnsupported):
				plans[i], err = nil, nil
			case err != nil:
				return fmt.Errorf("objectstore: list the versions of %s: %w", name, err)
			}
		}
		if len(plans[i]) > 0 {
			for _, version := range plans[i] {
				if version.DeleteMarker {
					continue
				}
				state, err := versioned.LockVersion(ctx, name, version.ID)
				switch {
				case errors.Is(err, ErrNotFound):
					continue
				case err != nil:
					return fmt.Errorf("objectstore: read the Object Lock of a version of %s: %w", name, err)
				}
				locked = mergeLock(locked, name, state, now)
			}
			continue
		}
		// A208: on a bucket with S3 Object Lock a plain delete only hides a
		// locked version behind a delete marker, so read the lock first.
		if locker, ok := store.(Locker); ok {
			state, err := locker.Lock(ctx, name)
			switch {
			case errors.Is(err, ErrNotFound):
				continue
			case err != nil:
				return fmt.Errorf("objectstore: read the Object Lock of %s: %w", name, err)
			}
			locked = mergeLock(locked, name, state, now)
		}
	}
	if locked != nil {
		return locked
	}
	for i, name := range names {
		if len(plans[i]) == 0 {
			if err := store.Delete(ctx, name); err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
			continue
		}
		for _, markers := range []bool{false, true} {
			for _, version := range plans[i] {
				if version.DeleteMarker != markers {
					continue
				}
				if err := versioned.DeleteVersion(ctx, name, version.ID); err != nil {
					return fmt.Errorf("objectstore: remove a version of %s: %w", name, err)
				}
			}
		}
	}
	return nil
}

// mergeLock adds one version's lock to the refusal, keeping the latest
// retention date and any legal hold.
func mergeLock(locked *ErrLocked, name string, state LockState, now time.Time) *ErrLocked {
	if !state.Locked(now) {
		return locked
	}
	if locked == nil {
		locked = &ErrLocked{Name: name}
	}
	locked.LegalHold = locked.LegalHold || state.LegalHold
	if until := state.RetainUntil; until != nil && now.Before(*until) && until.After(locked.Until) {
		locked.Until = *until
	}
	return locked
}

// RemoveAll deletes the tenant's objects rels for good, every version of
// each (see RemoveAll).
func (t Tenant) RemoveAll(ctx context.Context, rels ...string) error {
	names := make([]string, 0, len(rels))
	for _, rel := range rels {
		name, err := t.Name(rel)
		if err != nil {
			return err
		}
		names = append(names, name)
	}
	return RemoveAll(ctx, t.store, names...)
}
