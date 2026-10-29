// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// EventProtectionOffboardPolicy derives intent from the retained source. It
// cannot substitute a missing key, infer destruction or perform key I/O.
type EventProtectionOffboardPolicy interface {
	EventKeyDestructionForOffboard(context.Context, events.Event) (eventprotect.DestructionRequest, bool, error)
}

func WithEventProtectionOffboardPolicy(policy EventProtectionOffboardPolicy) Option {
	return func(projector *Projector) { projector.eventProtectionOffboardPolicy = policy }
}

func (p *Projector) offboardTenantTx(ctx context.Context, tx pgx.Tx, event events.Event) (store.TenantDeletionAttestation, error) {
	if p.eventProtectionOffboardPolicy != nil {
		request, protected, err := p.eventProtectionOffboardPolicy.EventKeyDestructionForOffboard(ctx, event)
		if err != nil {
			return store.TenantDeletionAttestation{}, err
		}
		if protected {
			return p.store.OffboardTenantForEventKeyDestructionTx(ctx, tx, request)
		}
	}
	return p.store.OffboardTenantTx(ctx, tx, event.TenantID)
}
