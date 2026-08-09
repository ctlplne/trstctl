// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reprotect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	decstore "trstctl.com/trstctl/ee/decommission/store"
	"trstctl.com/trstctl/internal/orchestrator"
	corestore "trstctl.com/trstctl/internal/store"
)

// ErrEnqueuerUnavailable reports a missing enqueue substrate (nil store or
// outbox). It is fail-closed: re-protection cannot be started without a place
// to durably record the intent.
var ErrEnqueuerUnavailable = errors.New("reprotect: enqueue substrate unavailable")

// Enqueuer is the production PRODUCER for DestinationJob. The handler in this
// package is a consumer with no other producer: until an operator-driven surface
// enqueues rows at "vdec.reprotect.job", the entire re-protection pipeline is
// unreachable however healthy it looks in the runtime roster (AUD-2).
//
// It plans one job per unaccounted dependent from the tenant's dependency-state
// read model and records each as an outbox row in a single tenant transaction
// (AN-6). Job identity is the jobmodel's stable idempotency key, and the insert
// is EnqueueIfAbsent, so a retried or replayed start enqueues nothing new
// (AN-5): asking twice never doubles the work.
type Enqueuer struct {
	store  *corestore.Store
	repo   *decstore.Repo
	outbox *orchestrator.Outbox
}

// NewEnqueuer builds the producer over the core store, the VDEC read-model
// repository, and the outbox that the server's dispatcher drains.
func NewEnqueuer(store *corestore.Store, repo *decstore.Repo, outbox *orchestrator.Outbox) *Enqueuer {
	return &Enqueuer{store: store, repo: repo, outbox: outbox}
}

// EnqueuedJob is the receipt row for one planned re-protection job. Enqueued is
// false when a row with the same stable idempotency key was already queued — the
// honest answer to a replayed start, not an error.
type EnqueuedJob struct {
	ID             string
	Kind           JobKind
	DependentClass string
	DependentRef   string
	Enqueued       bool
}

// EnqueueOutstanding plans and enqueues one re-protection job per unaccounted
// dependent of the key. found=false means the read model records no dependency
// state for this key at all, which the caller should surface rather than treat
// as "nothing to do" — an unknown key and a fully-accounted key are different
// answers.
func (e *Enqueuer) EnqueueOutstanding(ctx context.Context, tenantID, keyID string) (jobs []EnqueuedJob, found bool, err error) {
	if e == nil || e.store == nil || e.repo == nil || e.outbox == nil {
		return nil, false, ErrEnqueuerUnavailable
	}
	if tenantID == "" || keyID == "" {
		return nil, false, fmt.Errorf("%w: tenant and key are required", ErrInvalidState)
	}
	state, found, err := e.repo.FetchKeyState(ctx, tenantID, keyID)
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, nil
	}
	planned, err := PlanFromState(state)
	if err != nil {
		return nil, true, err
	}
	receipts := make([]EnqueuedJob, 0, len(planned))
	if len(planned) == 0 {
		return receipts, true, nil
	}
	err = e.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		for _, job := range planned {
			payload, err := json.Marshal(Payload{Job: job})
			if err != nil {
				return fmt.Errorf("reprotect: encode job payload: %w", err)
			}
			inserted, err := e.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
				TenantID:       tenantID,
				Destination:    DestinationJob,
				IdempotencyKey: job.IdempotencyKey,
				Payload:        payload,
			})
			if err != nil {
				return err
			}
			receipts = append(receipts, EnqueuedJob{
				ID:             job.ID,
				Kind:           job.Kind,
				DependentClass: string(job.Dependent.Class),
				DependentRef:   job.Dependent.ID,
				Enqueued:       inserted,
			})
		}
		return nil
	})
	if err != nil {
		return nil, true, err
	}
	return receipts, true, nil
}
