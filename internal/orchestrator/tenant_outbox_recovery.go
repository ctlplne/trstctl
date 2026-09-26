// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/events"
)

// beginTenantOutboxRecovery protects recovery of an existing intent, not a new
// command or an external call. Suspended customers keep their durable work; the
// dispatcher's ordinary service check still refuses execution. Events before
// the current registration, and events for erased tenants, cannot recreate work.
//
// Replay already pins history. Service admission uses a nonblocking advisory
// try-lock: contention aborts this pass without advancing its checkpoint, rather
// than waiting for an exclusive lifecycle operation that may need history.
func (o *Orchestrator) beginTenantOutboxRecovery(ctx context.Context, ev events.Event) (context.Context, func(), bool, error) {
	if o.tenantCommandService == nil || ev.TenantID == "" {
		// Standalone maintenance orchestrators have explicit recovery scope.
		// The served assembly always supplies tenant command admission.
		return ctx, func() {}, false, nil
	}
	if o.tenantCommandService.work == nil {
		return ctx, nil, false, errors.New("orchestrator: tenant recovery admission is incomplete")
	}
	ctx, release, err := o.tenantCommandService.work.Begin(ctx, ev.TenantID)
	if err != nil {
		return ctx, nil, false, err
	}
	tenant, err := o.store.GetTenant(ctx, ev.TenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ctx, release, true, nil
	}
	if err != nil {
		release()
		return ctx, nil, false, err
	}
	// Startup has already caught up the read model. EventSeq is the retained
	// registration position, not a mutable customer-status counter. It keeps a
	// reused UUID from inheriting its earlier registration's pending commands.
	if tenant.EventSeq == 0 || ev.Sequence == 0 {
		release()
		return ctx, nil, false, errors.New("orchestrator: outbox recovery lacks a retained registration or event sequence")
	}
	return ctx, release, ev.Sequence < tenant.EventSeq, nil
}
