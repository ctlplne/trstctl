// SPDX-License-Identifier: BUSL-1.1
package projections

import (
	"context"

	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

func (p *Projector) snapshotProtection(ctx context.Context) (store.SnapshotProtection, error) {
	planner := p.eventProtectionErasurePlanner
	if planner == nil {
		return nil, nil
	}
	if planner.Custody == nil {
		if planner.Policy.Log == nil {
			return nil, eventprivacy.ErrSource
		}
		activated := false
		err := planner.Policy.Log.WithHistoryRead(ctx, func(read context.Context) error {
			head, err := planner.Policy.Log.LastSequence(read)
			if err != nil {
				return err
			}
			return planner.Policy.Log.ReplayTypesThrough(read, 1, head, []string{eventprivacy.EventActivated}, func(events.Event) error { activated = true; return nil })
		})
		if err != nil {
			return nil, err
		}
		if activated {
			return nil, eventprivacy.ErrSource
		}
		return nil, nil
	}
	custody, ok := planner.Custody.(eventprivacy.SnapshotArtifactCustody)
	if !ok {
		return nil, eventprivacy.ErrSource
	}
	return eventprivacy.SourceSnapshotProtection{Policy: planner.Policy, Custody: custody}, nil
}
