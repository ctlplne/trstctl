// SPDX-License-Identifier: BUSL-1.1

package eventprotect

import (
	"context"
	"errors"
)

// DestructionReceipt reads current independent custody evidence. It never
// authorizes or performs removal, so it also works when a restored data cut
// predates the offboard command. A missing file is not a receipt. Active custody
// must still authenticate its material; completed custody must verify its signed
// record and read back key absence under the same cross-replica lock.
func (a *FileAuthority) DestructionReceipt(ctx context.Context, ref KeyRef) (string, bool, error) {
	var receipt string
	err := a.withLock(ctx, ref, func(_ context.Context, ref KeyRef) error {
		record, found, err := a.readRecord(ref)
		if err != nil || !found {
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
			receipt = record.Destruction.Receipt
			return nil
		default:
			return ErrKey
		}
	})
	if err != nil {
		return "", false, err
	}
	return receipt, receipt != "", nil
}
