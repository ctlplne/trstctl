// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
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

// Result codecs make the on-disk shape explicit. raw-v0 is a compatibility
// format for rows written before tenant-domain protection is attached. It keeps
// upgrades readable, but it is not the production-complete posture for
// credential-bearing responses.
const (
	ResultCodecRawV0                = "raw-v0"
	ResultCodecSealedRowV1          = "sealed-row-v1"
	ResultCodecSealedDynamicLeaseV1 = "sealed-dynamic-lease-v1"
)

// ResultProtector protects one opaque idempotency response before PostgreSQL or
// the in-memory test recorder retains it. tenantID, key, and binding are the
// authenticated row context: implementations must bind all three when sealing,
// then reject an Open when a protected row is copied to a different context.
//
// Open must also understand ResultCodecRawV0 as a migration-only pass-through,
// plus ResultCodecSealedDynamicLeaseV1 as an already-sealed inner envelope, so
// an attached protector can replay historical rows while they are being
// rewritten. Cryptographic implementations live behind internal/crypto (AN-3);
// this orchestrator interface only moves opaque []byte values across that
// boundary. Ownership of each returned byte slice transfers to the caller: an
// implementation must not alias an input, and the caller will wipe the returned
// storage after copying or consuming it.
type ResultProtector interface {
	Protect(ctx context.Context, tenantID, key, binding string, plaintext []byte) (codec string, protected []byte, err error)
	Open(ctx context.Context, tenantID, key, binding, codec string, protected []byte) ([]byte, error)
}

// IdempotencyOption configures an Idempotency recorder.
type IdempotencyOption func(*Idempotency)

// WithResultProtector attaches tenant-bound protection for every cached result
// writer and reader.
//
// This option is a rollout seam, not permission to enable protected writes on a
// mixed-version fleet. Every reader must understand result_codec first. Callers
// must also make a successful callback reconcilable before enabling it: fn does
// not receive this recorder's SQL transaction, so an independently committed
// event/effect cannot be rolled back if Protect or the result UPDATE later
// fails. Production assembly deliberately leaves this option unattached until
// that post-success failure wall is served.
func WithResultProtector(protector ResultProtector) IdempotencyOption {
	return func(idempotency *Idempotency) {
		idempotency.resultProtector = protector
	}
}

// Idempotency records every mutation under its Idempotency-Key (AN-5) so a
// replay returns the original result instead of executing again, and concurrent
// identical requests collapse to a single effect. A callback transfers ownership
// of its returned byte slice to Idempotency; the recorder copies the response for
// its caller/cache and wipes the callback-owned storage before returning.
type Idempotency struct {
	store           *store.Store
	memory          idemsvc.Idempotencer
	resultProtector ResultProtector

	memoryMu         sync.Mutex
	atMostOnceMemory map[string]atMostOnceMemoryResult
	boundMemory      map[string]*boundMemoryResult
}

type atMostOnceMemoryResult struct {
	completed bool
	codec     string
	result    []byte
}

type boundMemoryResult struct {
	binding   string
	persist   bool
	running   bool
	completed bool
	codec     string
	result    []byte
	wait      chan struct{}
}

// NewIdempotency returns an Idempotency backed by the given store.
func NewIdempotency(s *store.Store, options ...IdempotencyOption) *Idempotency {
	idempotency := &Idempotency{store: s}
	for _, option := range options {
		if option != nil {
			option(idempotency)
		}
	}
	return idempotency
}

// NewMemoryIdempotency returns an in-process idempotency recorder for served
// handler tests that exercise mutation routing without starting PostgreSQL.
func NewMemoryIdempotency(options ...IdempotencyOption) *Idempotency {
	idempotency := &Idempotency{memory: idemsvc.NewMemory()}
	for _, option := range options {
		if option != nil {
			option(idempotency)
		}
	}
	return idempotency
}

func (i *Idempotency) protectResult(ctx context.Context, tenantID, key, binding string, plaintext []byte) (string, []byte, error) {
	if i.resultProtector == nil {
		// This path exists only so a rolling upgrade can still read and write the
		// historical schema before the tenant crypto manager is wired. It is
		// deliberately labeled raw-v0 instead of pretending plaintext is sealed.
		return ResultCodecRawV0, append([]byte(nil), plaintext...), nil
	}
	codec, protected, err := i.resultProtector.Protect(ctx, tenantID, key, binding, plaintext)
	defer secret.Wipe(protected)
	if err != nil {
		return "", nil, fmt.Errorf("orchestrator: protect idempotency result: %w", err)
	}
	if codec == "" {
		return "", nil, errors.New("orchestrator: result protector returned an empty codec")
	}
	switch codec {
	case ResultCodecSealedRowV1:
		// The one writable protected format.
	case ResultCodecRawV0, ResultCodecSealedDynamicLeaseV1:
		return "", nil, fmt.Errorf("orchestrator: configured result protector may not write migration-only codec %q", codec)
	default:
		return "", nil, fmt.Errorf("orchestrator: result protector returned unsupported codec %q", codec)
	}
	if len(protected) == 0 {
		return "", nil, errors.New("orchestrator: result protector returned an empty protected result")
	}
	return codec, append([]byte(nil), protected...), nil
}

func (i *Idempotency) openResult(ctx context.Context, tenantID, key, binding, codec string, protected []byte) ([]byte, error) {
	// Every caller passes an owned SQL scan or memory-cache copy. Consume it here
	// so credential-bearing ciphertext/raw compatibility bytes do not linger
	// after replay, including on codec and protector errors.
	defer secret.Wipe(protected)
	if i.resultProtector == nil {
		switch codec {
		case ResultCodecRawV0:
			// Rolling-upgrade compatibility: these bytes have no outer
			// tenant-domain envelope yet.
		case ResultCodecSealedDynamicLeaseV1:
			// The pre-existing dynamic-lease API owns this inner CSL1 envelope
			// and opens it after idempotency replay. Keep it opaque until that
			// API-side wrapper is removed and the shared protector is attached.
		default:
			return nil, fmt.Errorf("orchestrator: result codec %q requires a configured result protector", codec)
		}
		return append([]byte(nil), protected...), nil
	}
	plaintext, err := i.resultProtector.Open(ctx, tenantID, key, binding, codec, protected)
	defer secret.Wipe(plaintext)
	if err != nil {
		return nil, fmt.Errorf("orchestrator: open idempotency result: %w", err)
	}
	return append([]byte(nil), plaintext...), nil
}

// Do runs fn at most once per (tenantID, key). The first caller for a key claims
// it, runs fn, and records the result; every later caller — a retry or a
// concurrent request — returns that recorded result without running fn again.
//
// The claim and cached result live in one tenant-scoped transaction, so
// row-level security confines the key to its tenant. fn runs while that
// transaction is open, but it does not receive the transaction: any event,
// database write, or external effect fn commits independently is not rolled back
// with this row. The claim is an
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
	var (
		result      []byte
		resultCodec string
		replayed    bool
	)
	defer func() { secret.Wipe(result) }()
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
				`SELECT result_codec, result FROM idempotency_keys
				 WHERE tenant_id = $1 AND key = $2 AND request_binding = ''`,
				tenantID, key).Scan(&resultCodec, &result); err != nil {
				return fmt.Errorf("orchestrator: load key result: %w", err)
			}
			replayed = true
			return nil
		}

		// We claimed the key: run the operation exactly once and record its
		// result in the same transaction as the claim.
		out, err := fn(ctx)
		defer secret.Wipe(out)
		if err != nil {
			return err
		}
		codec, protected, err := i.protectResult(ctx, tenantID, key, "", out)
		if err != nil {
			return err
		}
		defer secret.Wipe(protected)
		if _, err := tx.Exec(ctx,
			`UPDATE idempotency_keys
			 SET status = 'completed', result_codec = $3, result = $4, completed_at = now()
			 WHERE tenant_id = $1 AND key = $2 AND request_binding = ''`,
			tenantID, key, codec, protected); err != nil {
			return fmt.Errorf("orchestrator: record result: %w", err)
		}
		result = append([]byte(nil), out...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if replayed {
		return i.openResult(ctx, tenantID, key, "", resultCodec, result)
	}
	return append([]byte(nil), result...), nil
}

// DoBound is Do with an immutable request binding. It preserves Do's single
// tenant transaction for the key claim and cached result; as with Do, effects
// committed independently by fn do not share that transaction. A replay must
// present the same non-secret digest of the authenticated command before the
// recorded result can be loaded.
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

	var (
		result      []byte
		resultCodec string
		replayed    bool
	)
	defer func() { secret.Wipe(result) }()
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
				`SELECT result_codec, result FROM idempotency_keys
				 WHERE tenant_id = $1 AND key = $2 AND request_binding = $3`,
				tenantID, key, binding).Scan(&resultCodec, &result); err != nil {
				return fmt.Errorf("orchestrator: load bound result: %w", err)
			}
			replayed = true
			return nil
		}

		out, err := fn(ctx)
		defer secret.Wipe(out)
		if err != nil {
			return err
		}
		codec, protected, err := i.protectResult(ctx, tenantID, key, binding, out)
		if err != nil {
			return err
		}
		defer secret.Wipe(protected)
		tag, err = tx.Exec(ctx,
			`UPDATE idempotency_keys
			 SET status = 'completed', result_codec = $4, result = $5, completed_at = now()
			 WHERE tenant_id = $1 AND key = $2 AND request_binding = $3 AND status = 'pending'`,
			tenantID, key, binding, codec, protected)
		if err != nil {
			return fmt.Errorf("orchestrator: record bound result: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return ErrInProgress
		}
		result = append([]byte(nil), out...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if replayed {
		return i.openResult(ctx, tenantID, key, binding, resultCodec, result)
	}
	return append([]byte(nil), result...), nil
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
				codec := record.codec
				i.memoryMu.Unlock()
				return i.openResult(ctx, tenantID, key, binding, codec, result)
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
		var (
			codec     string
			protected []byte
		)
		if err == nil {
			codec, protected, err = i.protectResult(ctx, tenantID, key, binding, out)
		}

		i.memoryMu.Lock()
		record.running = false
		if err == nil {
			record.completed = true
			record.codec = codec
			record.result = append([]byte(nil), protected...)
		} else if !record.persist {
			delete(i.boundMemory, memoryKey)
		}
		close(record.wait)
		i.memoryMu.Unlock()
		secret.Wipe(protected)
		if err != nil {
			secret.Wipe(out)
			return nil, err
		}
		result := append([]byte(nil), out...)
		secret.Wipe(out)
		return result, nil
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
		secret.Wipe(out)
		return nil, err
	}
	defer secret.Wipe(out)
	codec, protected, err := i.protectResult(ctx, tenantID, key, "", out)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(protected)

	// Record the successful effect only after fn has returned and released every
	// external resource. The transaction below contains no callback or I/O.
	var (
		storedResult []byte
		resultCodec  string
		usedStored   bool
	)
	defer func() { secret.Wipe(storedResult) }()
	err = i.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`INSERT INTO idempotency_keys (tenant_id, key, status, result_codec, result, completed_at)
			 VALUES ($1, $2, 'completed', $3, $4, now())
			 ON CONFLICT (tenant_id, key) DO NOTHING`,
			tenantID, key, codec, protected)
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
			`SELECT result_codec, result FROM idempotency_keys
			 WHERE tenant_id = $1 AND key = $2 AND request_binding = ''`,
			tenantID, key).Scan(&resultCodec, &storedResult); err != nil {
			return fmt.Errorf("orchestrator: load outbox-effect response: %w", err)
		}
		usedStored = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if usedStored {
		return i.openResult(ctx, tenantID, key, "", resultCodec, storedResult)
	}
	return append([]byte(nil), out...), nil
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
		completed    bool
		storedResult []byte
		resultCodec  string
	)
	defer func() { secret.Wipe(storedResult) }()
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
				`SELECT result_codec, result FROM idempotency_keys
					  WHERE tenant_id = $1 AND key = $2 AND request_binding = $3`,
				tenantID, key, binding).Scan(&resultCodec, &storedResult); err != nil {
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
		return i.openResult(ctx, tenantID, key, binding, resultCodec, storedResult)
	}

	out, err := fn(ctx)
	if err != nil {
		secret.Wipe(out)
		return nil, err
	}
	defer secret.Wipe(out)
	codec, protected, err := i.protectResult(ctx, tenantID, key, binding, out)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(protected)
	usedStored := false
	err = i.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE idempotency_keys
			    SET status = 'completed', result_codec = $4, result = $5, completed_at = now()
			  WHERE tenant_id = $1 AND key = $2
			    AND status = 'bound' AND request_binding = $3`,
			tenantID, key, binding, codec, protected)
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
			`SELECT result_codec, result FROM idempotency_keys
			  WHERE tenant_id = $1 AND key = $2 AND request_binding = $3`,
			tenantID, key, binding).Scan(&resultCodec, &storedResult); err != nil {
			return fmt.Errorf("orchestrator: load completed bound durable result: %w", err)
		}
		usedStored = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if usedStored {
		return i.openResult(ctx, tenantID, key, binding, resultCodec, storedResult)
	}
	return append([]byte(nil), out...), nil
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
			return i.openResult(ctx, tenantID, key, "", prior.codec, append([]byte(nil), prior.result...))
		}
		i.atMostOnceMemory[memoryKey] = atMostOnceMemoryResult{}
		i.memoryMu.Unlock()
		out, err := fn(ctx)
		if err != nil {
			secret.Wipe(out)
			return nil, ErrEffectIndeterminate
		}
		defer secret.Wipe(out)
		codec, protected, err := i.protectResult(ctx, tenantID, key, "", out)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrEffectIndeterminate, err)
		}
		defer secret.Wipe(protected)
		i.memoryMu.Lock()
		i.atMostOnceMemory[memoryKey] = atMostOnceMemoryResult{
			completed: true,
			codec:     codec,
			result:    append([]byte(nil), protected...),
		}
		i.memoryMu.Unlock()
		return append([]byte(nil), out...), nil
	}
	if i.store == nil {
		return nil, errors.New("orchestrator: idempotency store is not configured")
	}

	var (
		claimed     bool
		result      []byte
		resultCodec string
	)
	defer func() { secret.Wipe(result) }()
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
			`SELECT result_codec, result FROM idempotency_keys
			 WHERE tenant_id = $1 AND key = $2 AND request_binding = ''`,
			tenantID, key).Scan(&resultCodec, &result); err != nil {
			return fmt.Errorf("orchestrator: load at-most-once result: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !claimed {
		return i.openResult(ctx, tenantID, key, "", resultCodec, result)
	}

	out, err := fn(ctx)
	if err != nil {
		secret.Wipe(out)
		// Deliberately retain the pending claim: without a provider-native lookup,
		// the process cannot prove whether the receiver committed before erroring.
		return nil, fmt.Errorf("%w", ErrEffectIndeterminate)
	}
	defer secret.Wipe(out)
	codec, protected, err := i.protectResult(ctx, tenantID, key, "", out)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEffectIndeterminate, err)
	}
	defer secret.Wipe(protected)
	err = i.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE idempotency_keys
			 SET status = 'completed', result_codec = $3, result = $4, completed_at = now()
			 WHERE tenant_id = $1 AND key = $2 AND status = 'pending' AND request_binding = ''`,
			tenantID, key, codec, protected)
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
	return append([]byte(nil), out...), nil
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
		if record, exists := i.boundMemory[memoryKey]; exists {
			if record.binding != "" {
				i.memoryMu.Unlock()
				return nil, ErrIdempotencyConflict
			}
			if !record.completed {
				i.memoryMu.Unlock()
				return nil, ErrInProgress
			}
			codec := record.codec
			result := append([]byte(nil), record.result...)
			i.memoryMu.Unlock()
			return i.openResult(ctx, tenantID, key, "", codec, result)
		}
		if record, exists := i.atMostOnceMemory[memoryKey]; exists {
			if !record.completed {
				i.memoryMu.Unlock()
				return nil, ErrInProgress
			}
			codec := record.codec
			result := append([]byte(nil), record.result...)
			i.memoryMu.Unlock()
			return i.openResult(ctx, tenantID, key, "", codec, result)
		}
		i.memoryMu.Unlock()
		return nil, ErrIdempotencyNotFound
	}
	if i.store == nil {
		return nil, errors.New("orchestrator: idempotency store is not configured")
	}
	var (
		status        string
		storedBinding string
		resultCodec   string
		result        []byte
	)
	defer func() { secret.Wipe(result) }()
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
			`SELECT result_codec, result FROM idempotency_keys
			 WHERE tenant_id = $1 AND key = $2 AND request_binding = ''`,
			tenantID, key).Scan(&resultCodec, &result); err != nil {
			return fmt.Errorf("orchestrator: load unbound key result: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return i.openResult(ctx, tenantID, key, "", resultCodec, result)
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
		record, ok := i.boundMemory[memoryKey]
		if !ok {
			i.memoryMu.Unlock()
			return nil, ErrIdempotencyNotFound
		}
		if !crypto.ConstantTimeEqual([]byte(record.binding), []byte(binding)) {
			i.memoryMu.Unlock()
			return nil, ErrIdempotencyConflict
		}
		if !record.completed {
			i.memoryMu.Unlock()
			return nil, ErrInProgress
		}
		codec := record.codec
		result := append([]byte(nil), record.result...)
		i.memoryMu.Unlock()
		return i.openResult(ctx, tenantID, key, binding, codec, result)
	}
	if i.store == nil {
		return nil, errors.New("orchestrator: idempotency store is not configured")
	}
	var (
		status        string
		storedBinding string
		resultCodec   string
		result        []byte
	)
	defer func() { secret.Wipe(result) }()
	err := i.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// The first query deliberately excludes result/result_codec. A caller with
		// a mismatched authenticated command must be rejected before PostgreSQL
		// returns any credential-bearing bytes to this process.
		err := tx.QueryRow(ctx,
			`SELECT status, request_binding
			   FROM idempotency_keys
			  WHERE tenant_id = $1 AND key = $2`,
			tenantID, key).Scan(&status, &storedBinding)
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
		if err := tx.QueryRow(ctx,
			`SELECT result_codec, result
			   FROM idempotency_keys
			  WHERE tenant_id = $1 AND key = $2 AND request_binding = $3`,
			tenantID, key, binding).Scan(&resultCodec, &result); err != nil {
			return fmt.Errorf("orchestrator: load authenticated bound result: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return i.openResult(ctx, tenantID, key, binding, resultCodec, result)
}
