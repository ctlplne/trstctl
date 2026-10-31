// SPDX-License-Identifier: BUSL-1.1
package eventprotect

import (
	"context"
	"errors"
	"os"
)

// PendingDestruction reports an interrupted journal matching retained creation.
// It neither signs nor authorizes an effect. A caller must still reacquire the
// exact source/outbox grant through the destruction receiver before resuming.
func (a *FileAuthority) PendingDestruction(ctx context.Context, creation KeyCreationEvidence) (DestructionRequest, bool, error) {
	if validateCreationEvidence(creation) != nil {
		return DestructionRequest{}, false, ErrKey
	}
	var result DestructionRequest
	var pending bool
	err := a.withLock(ctx, creation.Ref, func(_ context.Context, ref KeyRef) error {
		record, found, err := a.readRecord(ref)
		if err != nil || !found || creationEvidenceFor(record).Digest() != creation.Digest() {
			return ErrKey
		}
		switch record.Phase {
		case "active":
			key, err := a.loadKey(ref, record)
			if err != nil {
				return err
			}
			key.Destroy()
			return nil
		case "destroyed":
			if !errors.Is(a.destroyedState(record), ErrDestroyed) {
				return ErrKey
			}
			return nil
		case "destroying":
			if record.Destruction == nil || validateDestructionRequest(record.Destruction.Request) != nil || record.Destruction.Request.Ref != ref || record.Destruction.Request.CreationDigest != creation.Digest() || record.CreatedAt.After(record.Destruction.Request.OffboardedAt) || record.Destruction.Receipt != "" {
				return ErrKey
			}
			if !record.Destruction.RemovedAt.IsZero() && record.Destruction.RemovedAt.Before(record.Destruction.Request.NotBefore) {
				return ErrKey
			}
			if _, err := a.root.Lstat(keyName(ref)); err == nil {
				if !record.Destruction.RemovedAt.IsZero() {
					return ErrKey
				}
				key, err := a.loadKey(ref, record)
				if err != nil {
					return err
				}
				key.Destroy()
			} else if !errors.Is(err, os.ErrNotExist) {
				return ErrKey
			}
			result, pending = record.Destruction.Request, true
			return nil
		default:
			return ErrKey
		}
	})
	if err != nil {
		return DestructionRequest{}, false, err
	}
	return result, pending, nil
}
