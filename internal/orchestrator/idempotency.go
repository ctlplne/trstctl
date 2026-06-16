package orchestrator

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// ErrInProgress is returned when an idempotency key is found already claimed but
// not yet completed — a prior attempt is still running or crashed mid-flight.
// Recovering crashed in-flight operations is the outbox's job (AN-6, S2.5);
// within a single live process the claim transaction serializes retries so this
// is not observed.
//
// The idempotency_keys table this records into is bounded by a background
// retention sweep (internal/idemgc, SPINE-002), so it cannot grow without limit;
// AN-5 still holds within the retention window.
var ErrInProgress = errors.New("orchestrator: idempotent operation already in progress")

// Idempotency records every mutation under its Idempotency-Key (AN-5) so a
// replay returns the original result instead of executing again, and concurrent
// identical requests collapse to a single effect.
type Idempotency struct {
	store *store.Store
}

// NewIdempotency returns an Idempotency backed by the given store.
func NewIdempotency(s *store.Store) *Idempotency {
	return &Idempotency{store: s}
}

// Do runs fn at most once per (tenantID, key). The first caller for a key claims
// it, runs fn, and records the result; every later caller — a retry or a
// concurrent request — returns that recorded result without running fn again.
//
// Claim, execution, and result all live in one tenant-scoped transaction, so
// row-level security confines the key to its tenant. The claim is an
// INSERT ... ON CONFLICT (tenant_id, key) DO NOTHING: a concurrent identical
// request blocks on the winner's uncommitted row and, once the winner commits,
// observes the conflict (zero rows affected) and reads the cached result — so
// only one effect occurs. If fn fails, the transaction rolls back and the claim
// disappears, so a later retry is free to execute (failures are not cached).
func (i *Idempotency) Do(ctx context.Context, tenantID, key string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
	var result []byte
	err := i.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`INSERT INTO idempotency_keys (tenant_id, key, status)
			 VALUES ($1, $2, 'pending')
			 ON CONFLICT (tenant_id, key) DO NOTHING`,
			tenantID, key)
		if err != nil {
			return fmt.Errorf("orchestrator: claim key: %w", err)
		}

		if tag.RowsAffected() == 0 {
			// The key already exists (recorded earlier, or just committed by a
			// concurrent winner): return the stored result rather than re-run.
			var (
				status string
				stored []byte
			)
			if err := tx.QueryRow(ctx,
				`SELECT status, result FROM idempotency_keys
				 WHERE tenant_id = $1 AND key = $2`,
				tenantID, key).Scan(&status, &stored); err != nil {
				return fmt.Errorf("orchestrator: load key: %w", err)
			}
			if status != "completed" {
				return ErrInProgress
			}
			result = stored
			return nil
		}

		// We claimed the key: run the operation exactly once and record its
		// result in the same transaction as the claim.
		out, err := fn(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE idempotency_keys
			 SET status = 'completed', result = $3, completed_at = now()
			 WHERE tenant_id = $1 AND key = $2`,
			tenantID, key, out); err != nil {
			return fmt.Errorf("orchestrator: record result: %w", err)
		}
		result = out
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
