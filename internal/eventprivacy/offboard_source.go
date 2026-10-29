// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"context"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
)

// EventKeyDestructionForOffboard derives public intent only. It never opens a
// key, so deleting ordinary tenant rows can proceed during a custody outage.
// The committed receiver invocation and current independent custody still gate
// the destructive effect. Unknown or changed source coordinates refuse.
func (policy SourcePolicy) EventKeyDestructionForOffboard(ctx context.Context, event events.Event) (eventprotect.DestructionRequest, bool, error) {
	tenant, err := uuid.Parse(event.TenantID)
	if err != nil || tenant == uuid.Nil || event.Type != eventOffboarded || event.SchemaVersion != 1 || event.Sequence == 0 {
		return eventprotect.DestructionRequest{}, false, ErrSource
	}
	var result eventprotect.DestructionRequest
	var protected, found bool
	err = policy.replayLifetimes(ctx, tenant.String(), func(life Lifetime) error {
		if life.Offboard == nil || life.Offboard.ID != event.ID {
			return nil
		}
		if found || life.Offboard.Sequence != event.Sequence || !life.Offboard.Time.Equal(event.Time) {
			return ErrSource
		}
		found = true
		if life.Activation == nil {
			return nil
		}
		var err error
		result, err = NewDestructionRequest(life)
		protected = err == nil
		return err
	})
	if err != nil {
		return eventprotect.DestructionRequest{}, false, err
	}
	if !found {
		return eventprotect.DestructionRequest{}, false, ErrSource
	}
	return result, protected, nil
}
