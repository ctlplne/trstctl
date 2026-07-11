// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	idemsvc "trstctl.com/trstctl/internal/idem"
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

// ErrIdempotencyNotFound means no operation has claimed the requested key yet.
var ErrIdempotencyNotFound = errors.New("orchestrator: idempotent operation not found")

// ErrIdempotencyConflict means the caller reused a raw Idempotency-Key for a
// different authenticated command. Returning the first command's result would
// disclose it to the wrong caller; executing the new command would create a
// second effect. The only safe answer is a 409 at the transport boundary.
var ErrIdempotencyConflict = errors.New("orchestrator: idempotency key was already used for a different authenticated request")

// ErrEffectIndeterminate means a non-replay-safe receiver was claimed before its
// external call, but no completed result was durably recorded. Retrying the call
// could duplicate an upstream mutation, so the safe direction is operator
// reconciliation rather than blind redelivery.
var ErrEffectIndeterminate = errors.New("orchestrator: external effect outcome is indeterminate; reconciliation required")

// Idempotency records every mutation under its Idempotency-Key (AN-5) so a
// replay returns the original result instead of executing again, and concurrent
// identical requests collapse to a single effect.
type Idempotency struct {
	store  *store.Store
	memory idemsvc.Idempotencer

	memoryMu         sync.Mutex
	atMostOnceMemory map[string]atMostOnceMemoryResult
	boundMemory      map[string]*boundMemoryResult
}

type atMostOnceMemoryResult struct {
	completed bool
	result    []byte
}

type boundMemoryResult struct {
	binding   string
	persist   bool
	running   bool
	completed bool
	result    []byte
	wait      chan struct{}
}

// NewIdempotency returns an Idempotency backed by the given store.
func NewIdempotency(s *store.Store) *Idempotency {
	return &Idempotency{store: s}
}

// NewMemoryIdempotency returns an in-process idempotency recorder for served
// handler tests that exercise mutation routing without starting PostgreSQL.
func NewMemoryIdempotency() *Idempotency {
	return &Idempotency{memory: idemsvc.NewMemory()}
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
	if i == nil {
		return nil, errors.New("orchestrator: idempotency store is not configured")
	}
	if i.memory != nil {
		return i.doBoundMemory(ctx, tenantID, key, "", false, fn)
	}
	if i.store == nil {
		return nil, errors.New("orchestrator: idempotency store is not configured")
	}
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
			// concurrent winner). Check the non-secret namespace binding before
			// asking PostgreSQL for any cached response bytes.
			var status, storedBinding string
			if err := tx.QueryRow(ctx,
				`SELECT status, request_binding FROM idempotency_keys
				 WHERE tenant_id = $1 AND key = $2`,
				tenantID, key).Scan(&status, &storedBinding); err != nil {
				return fmt.Errorf("orchestrator: load key: %w", err)
			}
			if storedBinding != "" {
				return ErrIdempotencyConflict
			}
			if status != "completed" {
				return ErrInProgress
			}
			if err := tx.QueryRow(ctx,
				`SELECT result FROM idempotency_keys
				 WHERE tenant_id = $1 AND key = $2 AND request_binding = ''`,
				tenantID, key).Scan(&result); err != nil {
				return fmt.Errorf("orchestrator: load key result: %w", err)
			}
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
			 WHERE tenant_id = $1 AND key = $2 AND request_binding = ''`,
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

// DoBound is Do with an immutable request binding. It preserves Do's single
// tenant transaction: the key claim, fn, and completed result either commit
// together or all roll back. A replay must present the same non-secret digest
// of the authenticated command before the recorded result can be loaded.
// Reusing the raw key for another principal or route returns
// ErrIdempotencyConflict without running fn or returning cached bytes.
func (i *Idempotency) DoBound(ctx context.Context, tenantID, key, binding string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
	if i == nil {
		return nil, errors.New("orchestrator: idempotency store is not configured")
	}
	if tenantID == "" || key == "" || binding == "" {
		return nil, errors.New("orchestrator: bound idempotency requires tenant, key, and request binding")
	}
	if i.memory != nil {
		return i.doBoundMemory(ctx, tenantID, key, binding, false, fn)
	}
	if i.store == nil {
		return nil, errors.New("orchestrator: idempotency store is not configured")
	}

	var result []byte
	err := i.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`INSERT INTO idempotency_keys (tenant_id, key, status, request_binding)
			 VALUES ($1, $2, 'pending', $3)
			 ON CONFLICT (tenant_id, key) DO NOTHING`,
			tenantID, key, binding)
		if err != nil {
			return fmt.Errorf("orchestrator: claim bound key: %w", err)
		}

		if tag.RowsAffected() == 0 {
			// Read the non-secret binding before the credential-bearing result. A
			// mismatched caller must never cause cached response bytes to leave
			// PostgreSQL, even transiently inside the API process.
			var status, storedBinding string
			if err := tx.QueryRow(ctx,
				`SELECT status, request_binding FROM idempotency_keys
				 WHERE tenant_id = $1 AND key = $2`,
				tenantID, key).Scan(&status, &storedBinding); err != nil {
				return fmt.Errorf("orchestrator: load bound key: %w", err)
			}
			if !crypto.ConstantTimeEqual([]byte(storedBinding), []byte(binding)) {
				return ErrIdempotencyConflict
			}
			if status != "completed" {
				return ErrInProgress
			}
			if err := tx.QueryRow(ctx,
				`SELECT result FROM idempotency_keys
				 WHERE tenant_id = $1 AND key = $2 AND request_binding = $3`,
				tenantID, key, binding).Scan(&result); err != nil {
				return fmt.Errorf("orchestrator: load bound result: %w", err)
			}
			return nil
		}

		out, err := fn(ctx)
		if err != nil {
			return err
		}
		tag, err = tx.Exec(ctx,
			`UPDATE idempotency_keys
			 SET status = 'completed', result = $4, completed_at = now()
			 WHERE tenant_id = $1 AND key = $2 AND request_binding = $3 AND status = 'pending'`,
			tenantID, key, binding, out)
		if err != nil {
			return fmt.Errorf("orchestrator: record bound result: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return ErrInProgress
		}
		result = out
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// doBoundMemory is the in-process model shared by transactional and durable
// bound calls. It owns cached result bytes and makes identical concurrent calls
// wait for one callback. Transactional claims disappear on callback failure,
// matching a rolled-back DoBound transaction; durable claims persist so only an
// identical retry may reconcile an independently durable receiver.
func (i *Idempotency) doBoundMemory(ctx context.Context, tenantID, key, binding string, persist bool, fn func(context.Context) ([]byte, error)) ([]byte, error) {
	memoryKey := tenantID + "\x00" + key
	for {
		i.memoryMu.Lock()
		if i.boundMemory == nil {
			i.boundMemory = make(map[string]*boundMemoryResult)
		}
		if _, exists := i.atMostOnceMemory[memoryKey]; exists {
			i.memoryMu.Unlock()
			return nil, ErrIdempotencyConflict
		}
		record, exists := i.boundMemory[memoryKey]
		if exists {
			if !crypto.ConstantTimeEqual([]byte(record.binding), []byte(binding)) {
				// A transactional binding is not committed until its callback
				// succeeds. Wait to learn whether it commits or rolls back before
				// deciding whether a different command conflicts.
				if record.running && !record.persist {
					wait := record.wait
					i.memoryMu.Unlock()
					select {
					case <-wait:
						continue
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
				i.memoryMu.Unlock()
				return nil, ErrIdempotencyConflict
			}
			if record.completed {
				result := append([]byte(nil), record.result...)
				i.memoryMu.Unlock()
				return result, nil
			}
			if record.running {
				wait := record.wait
				i.memoryMu.Unlock()
				select {
				case <-wait:
					continue
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			if record.persist && !persist {
				i.memoryMu.Unlock()
				return nil, ErrInProgress
			}
			record.persist = record.persist || persist
			record.running = true
			record.wait = make(chan struct{})
		} else {
			record = &boundMemoryResult{
				binding: binding,
				persist: persist,
				running: true,
				wait:    make(chan struct{}),
			}
			i.boundMemory[memoryKey] = record
		}
		i.memoryMu.Unlock()

		out, err := fn(ctx)

		i.memoryMu.Lock()
		record.running = false
		if err == nil {
			record.completed = true
			record.result = append([]byte(nil), out...)
		} else if !record.persist {
			delete(i.boundMemory, memoryKey)
		}
		close(record.wait)
		i.memoryMu.Unlock()
		if err != nil {
			return out, err
		}
		return append([]byte(nil), out...), nil
	}
}

// DoDurableEffect runs an already-durable effect without holding a
// PostgreSQL transaction or pool connection while fn performs network,
// filesystem, HSM, or process I/O. It first returns any completed result, then
// runs fn, and finally records that result in a short tenant-scoped transaction.
//
// fn MUST delegate to an independently durable, idempotent receiver using this
// same stable key (for example an outbox-owned connector fingerprint, provider
// request token, or event-projected operation id). Receiver-side idempotency closes
// the unavoidable crash window between the effect succeeding and this process
// recording its result. A normal in-process API mutation must keep using Do so its
// database state and idempotency record commit atomically.
func (i *Idempotency) DoDurableEffect(ctx context.Context, tenantID, key string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
	if i == nil {
		return nil, errors.New("orchestrator: idempotency store is not configured")
	}
	// The in-memory implementation owns no database transaction or connection.
	// Keeping its existing single-flight behavior makes assembled-handler tests
	// deterministic without weakening the production PostgreSQL path below.
	if i.memory != nil {
		return i.doBoundMemory(ctx, tenantID, key, "", false, fn)
	}
	if i.store == nil {
		return nil, errors.New("orchestrator: idempotency store is not configured")
	}

	if result, err := i.Result(ctx, tenantID, key); err == nil {
		return result, nil
	} else if !errors.Is(err, ErrIdempotencyNotFound) {
		// A pending row can only come from a transactional Do caller (or an older
		// release). Do not race that owner by performing a second external effect.
		return nil, err
	}

	out, err := fn(ctx)
	if err != nil {
		return nil, err
	}

	// Record the successful effect only after fn has returned and released every
	// external resource. The transaction below contains no callback or I/O.
	result := out
	err = i.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`INSERT INTO idempotency_keys (tenant_id, key, status, result, completed_at)
			 VALUES ($1, $2, 'completed', $3, now())
			 ON CONFLICT (tenant_id, key) DO NOTHING`,
			tenantID, key, out)
		if err != nil {
			return fmt.Errorf("orchestrator: record outbox-effect result: %w", err)
		}
		if tag.RowsAffected() != 0 {
			return nil
		}

		// A lease-expiry race may let two idempotent receiver calls finish. The
		// first completed unbound result is authoritative for every replay, but
		// a bound API row belongs to a different authenticated command namespace.
		var status, storedBinding string
		if err := tx.QueryRow(ctx,
			`SELECT status, request_binding FROM idempotency_keys
			 WHERE tenant_id = $1 AND key = $2`,
			tenantID, key).Scan(&status, &storedBinding); err != nil {
			return fmt.Errorf("orchestrator: load outbox-effect result: %w", err)
		}
		if storedBinding != "" {
			return ErrIdempotencyConflict
		}
		if status != "completed" {
			return ErrInProgress
		}
		if err := tx.QueryRow(ctx,
			`SELECT result FROM idempotency_keys
			 WHERE tenant_id = $1 AND key = $2 AND request_binding = ''`,
			tenantID, key).Scan(&result); err != nil {
			return fmt.Errorf("orchestrator: load outbox-effect response: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// DoDurableEffectBound is DoDurableEffect with an immutable request binding
// claimed before fn runs. binding is a non-secret digest of the authenticated
// principal plus the canonical command. A process crash after the durable
// receiver commits leaves the claim in "bound" state: an identical retry may
// reconcile the receiver, while a changed command or caller fails closed before
// any callback or credential-bearing result is opened.
//
// Like DoDurableEffect, fn MUST use an independently durable receiver keyed by
// the same raw Idempotency-Key. Concurrent identical callers may reach that
// receiver; the receiver must collapse them to one effect. Only the first
// completed HTTP result becomes authoritative.
func (i *Idempotency) DoDurableEffectBound(ctx context.Context, tenantID, key, binding string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
	if i == nil {
		return nil, errors.New("orchestrator: idempotency store is not configured")
	}
	if tenantID == "" || key == "" || binding == "" {
		return nil, errors.New("orchestrator: bound durable idempotency requires tenant, key, and request binding")
	}
	if i.memory != nil {
		return i.doBoundMemory(ctx, tenantID, key, binding, true, fn)
	}
	if i.store == nil {
		return nil, errors.New("orchestrator: idempotency store is not configured")
	}

	var (
		completed bool
		result    []byte
	)
	err := i.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`INSERT INTO idempotency_keys (tenant_id, key, status, request_binding)
			 VALUES ($1, $2, 'bound', $3)
			 ON CONFLICT (tenant_id, key) DO NOTHING`,
			tenantID, key, binding)
		if err != nil {
			return fmt.Errorf("orchestrator: bind durable key: %w", err)
		}
		if tag.RowsAffected() == 1 {
			return nil
		}

		var status, storedBinding string
		if err := tx.QueryRow(ctx,
			`SELECT status, request_binding
			   FROM idempotency_keys
			  WHERE tenant_id = $1 AND key = $2`,
			tenantID, key).Scan(&status, &storedBinding); err != nil {
			return fmt.Errorf("orchestrator: load bound durable key: %w", err)
		}
		if !crypto.ConstantTimeEqual([]byte(storedBinding), []byte(binding)) {
			return ErrIdempotencyConflict
		}
		switch status {
		case "bound":
			return nil
		case "completed":
			if err := tx.QueryRow(ctx,
				`SELECT result FROM idempotency_keys
				  WHERE tenant_id = $1 AND key = $2 AND request_binding = $3`,
				tenantID, key, binding).Scan(&result); err != nil {
				return fmt.Errorf("orchestrator: load bound durable result: %w", err)
			}
			completed = true
			return nil
		default:
			return ErrInProgress
		}
	})
	if err != nil {
		return nil, err
	}
	if completed {
		return result, nil
	}

	out, err := fn(ctx)
	if err != nil {
		return nil, err
	}
	result = out
	err = i.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE idempotency_keys
			    SET status = 'completed', result = $4, completed_at = now()
			  WHERE tenant_id = $1 AND key = $2
			    AND status = 'bound' AND request_binding = $3`,
			tenantID, key, binding, out)
		if err != nil {
			return fmt.Errorf("orchestrator: complete bound durable key: %w", err)
		}
		if tag.RowsAffected() == 1 {
			return nil
		}

		var status, storedBinding string
		if err := tx.QueryRow(ctx,
			`SELECT status, request_binding
			   FROM idempotency_keys
			  WHERE tenant_id = $1 AND key = $2`,
			tenantID, key).Scan(&status, &storedBinding); err != nil {
			return fmt.Errorf("orchestrator: load completed bound durable key: %w", err)
		}
		if !crypto.ConstantTimeEqual([]byte(storedBinding), []byte(binding)) {
			return ErrIdempotencyConflict
		}
		if status != "completed" {
			return ErrInProgress
		}
		if err := tx.QueryRow(ctx,
			`SELECT result FROM idempotency_keys
			  WHERE tenant_id = $1 AND key = $2 AND request_binding = $3`,
			tenantID, key, binding).Scan(&result); err != nil {
			return fmt.Errorf("orchestrator: load completed bound durable result: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// DoAtMostOnceEffect protects an external receiver that has no proven replay
// token or lookup-by-operation API. It commits a pending claim in a short tenant
// transaction before fn begins, releases the database connection for the call,
// and records the result afterward. A crash/error after the claim leaves the key
// pending; every replay then returns ErrEffectIndeterminate without calling fn.
// This trades automatic retry for the only safe no-duplicate behavior available
// when the upstream cannot participate in exactly-once delivery.
func (i *Idempotency) DoAtMostOnceEffect(ctx context.Context, tenantID, key string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
	if i == nil {
		return nil, errors.New("orchestrator: idempotency store is not configured")
	}
	if i.memory != nil {
		memoryKey := tenantID + "\x00" + key
		i.memoryMu.Lock()
		if _, exists := i.boundMemory[memoryKey]; exists {
			i.memoryMu.Unlock()
			return nil, ErrIdempotencyConflict
		}
		if i.atMostOnceMemory == nil {
			i.atMostOnceMemory = make(map[string]atMostOnceMemoryResult)
		}
		if prior, ok := i.atMostOnceMemory[memoryKey]; ok {
			i.memoryMu.Unlock()
			if !prior.completed {
				return nil, ErrEffectIndeterminate
			}
			return append([]byte(nil), prior.result...), nil
		}
		i.atMostOnceMemory[memoryKey] = atMostOnceMemoryResult{}
		i.memoryMu.Unlock()
		out, err := fn(ctx)
		if err != nil {
			return nil, ErrEffectIndeterminate
		}
		i.memoryMu.Lock()
		i.atMostOnceMemory[memoryKey] = atMostOnceMemoryResult{completed: true, result: append([]byte(nil), out...)}
		i.memoryMu.Unlock()
		return out, nil
	}
	if i.store == nil {
		return nil, errors.New("orchestrator: idempotency store is not configured")
	}

	var (
		claimed bool
		result  []byte
	)
	err := i.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`INSERT INTO idempotency_keys (tenant_id, key, status)
			 VALUES ($1, $2, 'pending')
			 ON CONFLICT (tenant_id, key) DO NOTHING`, tenantID, key)
		if err != nil {
			return fmt.Errorf("orchestrator: claim at-most-once effect: %w", err)
		}
		if tag.RowsAffected() == 1 {
			claimed = true
			return nil
		}
		var status, storedBinding string
		if err := tx.QueryRow(ctx,
			`SELECT status, request_binding FROM idempotency_keys
			 WHERE tenant_id = $1 AND key = $2`, tenantID, key).Scan(&status, &storedBinding); err != nil {
			return fmt.Errorf("orchestrator: load at-most-once effect: %w", err)
		}
		if storedBinding != "" {
			return ErrIdempotencyConflict
		}
		if status != "completed" {
			return ErrEffectIndeterminate
		}
		if err := tx.QueryRow(ctx,
			`SELECT result FROM idempotency_keys
			 WHERE tenant_id = $1 AND key = $2 AND request_binding = ''`,
			tenantID, key).Scan(&result); err != nil {
			return fmt.Errorf("orchestrator: load at-most-once result: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !claimed {
		return result, nil
	}

	out, err := fn(ctx)
	if err != nil {
		// Deliberately retain the pending claim: without a provider-native lookup,
		// the process cannot prove whether the receiver committed before erroring.
		return nil, fmt.Errorf("%w", ErrEffectIndeterminate)
	}
	err = i.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE idempotency_keys
			 SET status = 'completed', result = $3, completed_at = now()
			 WHERE tenant_id = $1 AND key = $2 AND status = 'pending' AND request_binding = ''`,
			tenantID, key, out)
		if err != nil {
			return fmt.Errorf("orchestrator: complete at-most-once effect: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return ErrEffectIndeterminate
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Result returns a completed legacy/unbound result without claiming or running
// the operation. It is used by request paths that enqueue an outbox row and then
// wait for the outbox worker to complete the external side effect. A row with a
// non-empty authenticated request binding is deliberately opaque to this method.
func (i *Idempotency) Result(ctx context.Context, tenantID, key string) ([]byte, error) {
	if i == nil {
		return nil, errors.New("orchestrator: idempotency store is not configured")
	}
	if i.memory != nil {
		memoryKey := tenantID + "\x00" + key
		i.memoryMu.Lock()
		defer i.memoryMu.Unlock()
		if record, exists := i.boundMemory[memoryKey]; exists {
			if record.binding != "" {
				return nil, ErrIdempotencyConflict
			}
			if !record.completed {
				return nil, ErrInProgress
			}
			return append([]byte(nil), record.result...), nil
		}
		if record, exists := i.atMostOnceMemory[memoryKey]; exists {
			if !record.completed {
				return nil, ErrInProgress
			}
			return append([]byte(nil), record.result...), nil
		}
		return nil, ErrIdempotencyNotFound
	}
	if i.store == nil {
		return nil, errors.New("orchestrator: idempotency store is not configured")
	}
	var (
		status        string
		storedBinding string
		result        []byte
	)
	err := i.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`SELECT status, request_binding FROM idempotency_keys
			 WHERE tenant_id = $1 AND key = $2`,
			tenantID, key).Scan(&status, &storedBinding)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrIdempotencyNotFound
		}
		if err != nil {
			return fmt.Errorf("orchestrator: load key result: %w", err)
		}
		if storedBinding != "" {
			return ErrIdempotencyConflict
		}
		if status != "completed" {
			return ErrInProgress
		}
		if err := tx.QueryRow(ctx,
			`SELECT result FROM idempotency_keys
			 WHERE tenant_id = $1 AND key = $2 AND request_binding = ''`,
			tenantID, key).Scan(&result); err != nil {
			return fmt.Errorf("orchestrator: load unbound key result: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// BoundResult returns a completed durable-effect result only when binding is the
// exact authenticated command that claimed key. A pending/bound claim remains in
// progress, and another caller or command receives a conflict. Unlike Result,
// this method never opens a legacy unbound result: callers must consciously pick
// the replay contract that created the row.
func (i *Idempotency) BoundResult(ctx context.Context, tenantID, key, binding string) ([]byte, error) {
	if i == nil || tenantID == "" || key == "" || binding == "" {
		return nil, errors.New("orchestrator: bound result requires tenant, key, and request binding")
	}
	if i.memory != nil {
		memoryKey := tenantID + "\x00" + key
		i.memoryMu.Lock()
		defer i.memoryMu.Unlock()
		record, ok := i.boundMemory[memoryKey]
		if !ok {
			return nil, ErrIdempotencyNotFound
		}
		if !crypto.ConstantTimeEqual([]byte(record.binding), []byte(binding)) {
			return nil, ErrIdempotencyConflict
		}
		if !record.completed {
			return nil, ErrInProgress
		}
		return append([]byte(nil), record.result...), nil
	}
	if i.store == nil {
		return nil, errors.New("orchestrator: idempotency store is not configured")
	}
	var (
		status        string
		storedBinding string
		result        []byte
	)
	err := i.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`SELECT status, request_binding, result
			   FROM idempotency_keys
			  WHERE tenant_id = $1 AND key = $2`,
			tenantID, key).Scan(&status, &storedBinding, &result)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrIdempotencyNotFound
		}
		if err != nil {
			return fmt.Errorf("orchestrator: load bound key result: %w", err)
		}
		if storedBinding == "" || !crypto.ConstantTimeEqual([]byte(storedBinding), []byte(binding)) {
			return ErrIdempotencyConflict
		}
		if status != "completed" {
			return ErrInProgress
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
