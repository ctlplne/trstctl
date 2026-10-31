// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/store"
)

// DestructionCleanup removes only operational metadata for an independently
// verified completed effect. It cannot remove a key or mint a removal grant.
type DestructionCleanup struct {
	Store   *store.Store
	Policy  SourcePolicy
	Custody CompletionFenceCustody
	active  atomic.Int64
	mu      sync.Mutex
	afterID int64
}

func (c *DestructionCleanup) Run(ctx context.Context) (int, error) {
	if c == nil || c.Store == nil || c.Policy.Log == nil || c.Custody == nil {
		return 0, ErrSource
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	c.active.Add(1)
	defer c.active.Add(-1)
	// No waiting queue: other family workers remain available for delivery.
	if !c.mu.TryLock() {
		return 0, nil
	}
	defer c.mu.Unlock()
	rows, err := c.Store.ListSettledEventKeyDestructionIntents(ctx, c.afterID)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 && c.afterID != 0 {
		// Wrap within this bounded call, so Drain cannot declare a false quiet
		// result solely because a cursor was beyond newly eligible old rows.
		c.afterID = 0
		rows, err = c.Store.ListSettledEventKeyDestructionIntents(ctx, 0)
		if err != nil {
			return 0, err
		}
	}
	if len(rows) == 0 {
		return 0, nil
	}
	c.afterID = rows[len(rows)-1].ID
	var joined error
	removed := 0
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return removed, errors.Join(joined, err)
		}
		done, err := c.remove(ctx, row)
		if err != nil {
			joined = errors.Join(joined, err)
			continue
		}
		if done {
			removed++
		}
	}
	return removed, joined
}

func (c *DestructionCleanup) remove(ctx context.Context, row store.SettledEventKeyDestructionIntent) (bool, error) {
	var request eventprotect.DestructionRequest
	if row.ID <= 0 || decodeEventKeyCommand(row.Payload, &request) != nil || request.Validate() != nil || request.Ref.TenantID != row.TenantID || row.IdempotencyKey != store.EventKeyDestructionOutboxKey(request.OperationID) {
		return false, ErrSource
	}
	life, found, err := c.Policy.LifetimeForKey(ctx, request.Ref)
	if err != nil {
		return false, err
	}
	if !found || life.Completion == nil || !sameDestructionRequest(life.Completion.Claims.Request, request) {
		return false, ErrSource
	}
	event, found, err := c.Policy.Log.EventAtSequence(ctx, life.Completion.Meta.Sequence)
	if err != nil {
		return false, err
	}
	if !found {
		return false, ErrSource
	}
	verifier := CompletionVerifier{Policy: c.Policy, Custody: c.Custody}
	removed := false
	err = c.Store.WithTenant(ctx, request.Ref.TenantID, func(tx pgx.Tx) error {
		return verifier.WithVerifiedCompletion(ctx, event, func(verified context.Context, actual eventprotect.DestructionRequest) error {
			if !sameDestructionRequest(actual, request) {
				return ErrSource
			}
			var err error
			removed, err = c.Store.RemoveSettledEventKeyDestructionTx(verified, tx, actual)
			return err
		})
	})
	return removed, err
}

// Active is independent of removal counts. Drain must wait for an older pooled
// cleanup even if its own non-queued calls found that helper busy.
func (c *DestructionCleanup) Active() bool { return c != nil && c.active.Load() > 0 }
