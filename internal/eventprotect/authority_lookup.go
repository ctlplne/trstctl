// SPDX-License-Identifier: BUSL-1.1
package eventprotect

import (
	"context"
	"errors"
	"os"
)

type CustodyKeyPhase string

const (
	CustodyKeyPreparing CustodyKeyPhase = "preparing"
	CustodyKeyActive    CustodyKeyPhase = "active"
	CustodyKeyPending   CustodyKeyPhase = "pending"
	CustodyKeyDestroyed CustodyKeyPhase = "destroyed"
)

// CurrentKeyState is public creation identity and independently verified status,
// never a key, wrapped key or grant to sign/remove/provision.
type CurrentKeyState struct {
	Phase    CustodyKeyPhase
	Creation KeyCreationEvidence
	Receipt  string
}

// LookupKeyState distinguishes a never-enabled reference from lost material.
// Completed state requires the original pinned signature and CURRENT absence.
func (a *FileAuthority) LookupKeyState(ctx context.Context, ref KeyRef) (CurrentKeyState, bool, error) {
	var result CurrentKeyState
	var exists bool
	err := a.withLock(ctx, ref, func(_ context.Context, ref KeyRef) error {
		record, found, err := a.readRecord(ref)
		exists = found
		if err != nil {
			return err
		}
		if !found {
			if _, err := a.root.Lstat(keyName(ref)); !errors.Is(err, os.ErrNotExist) {
				exists = true
				return ErrKey
			}
			return nil
		}
		result.Creation = creationEvidenceFor(record)
		switch record.Phase {
		case "creating":
			if record.Destruction != nil {
				return ErrKey
			}
			result.Phase = CustodyKeyPreparing
		case "active":
			if result.Creation.Digest() == "" || record.Destruction != nil {
				return ErrKey
			}
			key, err := a.loadKey(ref, record)
			if err != nil {
				return err
			}
			key.Destroy()
			result.Phase = CustodyKeyActive
		case "destroying":
			if _, err := a.pendingDestructionRecord(ref, record); err != nil {
				return err
			}
			result.Phase = CustodyKeyPending
		case "destroyed":
			if !errors.Is(a.destroyedState(record), ErrDestroyed) {
				return ErrKey
			}
			result.Phase = CustodyKeyDestroyed
			result.Receipt = record.Destruction.Receipt
		default:
			return ErrKey
		}
		return nil
	})
	if err != nil {
		return CurrentKeyState{}, exists, err
	}
	return result, exists, nil
}
