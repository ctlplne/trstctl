// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/store"
)

// holdClaim keeps a claim's lease ahead of its expiry while this worker
// delivers it (A98-L1). A claim's lease is how long the row stays this
// worker's; load that slowed a delivery past it (a slow receiver, a busy
// datastore between the claim and the finalize) let another worker recover
// the row and deliver it a second time. Every third of a lease the hold
// moves lease_until one lease ahead, but only while the row is still this
// worker's attempt, and never past the claim's
// delivery deadline plus one lease: a worker that hangs past its deadline
// still loses the row to recovery, as before. One goroutine per claim in
// flight, ended by the returned release (or the dispatch context).
func (o *Outbox) holdClaim(ctx context.Context, claim claimedOutboxEntry) (release func()) {
	if o.leaseTTL <= 0 || o.deliveryTimeout <= 0 || claim.claimedAt.IsZero() {
		return func() {}
	}
	limit := claim.claimedAt.Add(o.deliveryTimeout + o.leaseTTL)
	holdCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(o.leaseTTL / 3)
		defer tick.Stop()
		for {
			select {
			case <-holdCtx.Done():
				return
			case <-tick.C:
			}
			now := o.clockNow()
			until := now.Add(o.leaseTTL)
			if until.After(limit) {
				until = limit
			}
			if !until.After(now) {
				return // the hold limit: the lease now runs out
			}
			if held, err := o.extendClaimLease(holdCtx, claim, until); err != nil || !held {
				return // lost, finalized, or unreachable: finalize reports which
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

// extendClaimLease moves this exact attempt's lease to until; it never shortens
// one. Recovery may have taken an expired lease, in which case the row's
// status, worker or attempt has changed and this update must do nothing.
func (o *Outbox) extendClaimLease(ctx context.Context, claim claimedOutboxEntry, until time.Time) (bool, error) {
	var held bool
	err := o.store.WithSystemFirst(ctx,
		`UPDATE outbox
		    SET lease_until = GREATEST(lease_until, $5)
		  WHERE id = $1
		    AND tenant_id = $2
		    AND status = 'processing'
		    AND worker_id = $3
		    AND attempts = $4`,
		[]any{claim.id, claim.msg.TenantID, o.workerID, claim.attempts, until},
		func(tag pgconn.CommandTag, err error, _ store.TxStatements) error {
			if err != nil {
				return err
			}
			held = tag.RowsAffected() == 1
			return nil
		})
	return held, err
}
