// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
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

// ErrEffectIndeterminate means a callback/receiver may have succeeded, but no
// completed result was durably recorded. Retrying the callback could duplicate a
// mutation, so the safe direction is a named subsystem reconciler or operator
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
// Production protectors accept only ResultCodecSealedRowV1 at runtime. The
// pre-readiness migrator consumes raw-v0 and sealed-dynamic-lease-v1 directly
// and rewrites them before a mutation surface opens; keeping compatibility in
// Open would silently preserve a plaintext read path after the ratchet.
// Cryptographic implementations live behind internal/crypto (AN-3); this
// interface only moves opaque []byte values across that boundary. Ownership of
// each returned byte slice transfers to the caller: an implementation must not
// alias an input, and the caller will wipe the returned storage after copying
// or consuming it.
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
// must also make independently committed callback effects reconcilable before
// enabling it. The recorder durably walls off a key when protection/completion
// fails after fn succeeds, but it cannot invent the lost successful response;
// only a named subsystem reconciler can resolve that indeterminate operation.
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

	protectedFlightMu sync.Mutex
	protectedFlights  map[string]chan struct{}
}

type atMostOnceMemoryResult struct {
	completed bool
	codec     string
	result    []byte
}

type boundMemoryResult struct {
	binding       string
	persist       bool
	running       bool
	completed     bool
	indeterminate bool
	codec         string
	result        []byte
	wait          chan struct{}
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

// schedulerPrivacyCachedResponse mirrors the generic HTTP idempotency envelope
// without coupling the orchestrator back to internal/api. Its compact field
// names are a durable storage contract: the scheduler's terminal tick stores
// the exact Body and Status that this protected envelope must authenticate.
type schedulerPrivacyCachedResponse struct {
	Status  int             `json:"s"`
	Body    json.RawMessage `json:"b"`
	Binding string          `json:"h,omitempty"`
}

// ResolveSecretRotationSchedulePrivacyOuter is the generic idempotency
// receiver owner's same-transaction privacy seam. The caller already holds the
// exact row lock in tx. This method authenticates the cached HTTP envelope,
// re-protects it under the replacement key's AAD when the raw key changes, and
// installs the result with an exact old-row CAS before returning an
// acknowledgement. It never opens a second SQL mutation transaction.
func (i *Idempotency) ResolveSecretRotationSchedulePrivacyOuter(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, rawIdempotencyKey string,
	requirement store.SecretRotationSchedulePrivacyOuterRequirement,
) (store.SecretRotationSchedulePrivacyOuterAcknowledgement, error) {
	var acknowledgement store.SecretRotationSchedulePrivacyOuterAcknowledgement
	if i == nil || i.store == nil || tx == nil || tenantID == "" ||
		rawIdempotencyKey == "" || requirement.AuthorityRef == "" ||
		requirement.RequestBinding == "" || requirement.Status == "" ||
		requirement.ReplacementIdempotencyKey == "" {
		return acknowledgement, errors.New("orchestrator: scheduler privacy outer resolver is incomplete")
	}

	var status, binding, codec string
	var protected []byte
	if err := tx.QueryRow(ctx,
		`SELECT status, request_binding, result_codec, result
		   FROM idempotency_keys
		  WHERE tenant_id = $1 AND key = $2
		  FOR UPDATE`, tenantID, rawIdempotencyKey).Scan(
		&status, &binding, &codec, &protected); err != nil {
		return acknowledgement, fmt.Errorf("orchestrator: lock scheduler privacy outer receiver: %w", err)
	}
	defer secret.Wipe(protected)
	if status != requirement.Status ||
		!crypto.ConstantTimeEqual([]byte(binding), []byte(requirement.RequestBinding)) ||
		codec != requirement.ResultCodec {
		return acknowledgement, fmt.Errorf(
			"%w: scheduler privacy outer receiver differs from its locked requirement",
			store.ErrSecretRotationScheduleTickConflict,
		)
	}
	if requirement.RawKeyTokenMatch ==
		(requirement.ReplacementIdempotencyKey == rawIdempotencyKey) {
		return acknowledgement, fmt.Errorf(
			"%w: scheduler privacy outer replacement key contradicts raw-key match",
			store.ErrSecretRotationScheduleTickConflict,
		)
	}

	acknowledgement = store.SecretRotationSchedulePrivacyOuterAcknowledgement{
		AuthorityRef:           requirement.AuthorityRef,
		RequestBinding:         binding,
		OriginalResultCodec:    codec,
		ResolvedIdempotencyKey: requirement.ReplacementIdempotencyKey,
		ResolvedResultCodec:    codec,
	}

	switch status {
	case "bound":
		if !requirement.RawKeyTokenMatch || requirement.TerminalBodyMatch ||
			requirement.TerminalHTTPStatus != 0 || len(requirement.OriginalTerminalBody) != 0 ||
			len(requirement.RewrittenTerminalBody) != 0 || codec == "" || len(protected) != 0 {
			return store.SecretRotationSchedulePrivacyOuterAcknowledgement{}, fmt.Errorf(
				"%w: bound scheduler privacy outer has terminal result evidence",
				store.ErrSecretRotationScheduleTickConflict,
			)
		}
		tag, err := tx.Exec(ctx,
			`UPDATE idempotency_keys
			    SET key = $3
			  WHERE tenant_id = $1 AND key = $2
			    AND status = $4 AND request_binding = $5
			    AND result_codec = $6 AND result IS NOT DISTINCT FROM $7`,
			tenantID, rawIdempotencyKey, requirement.ReplacementIdempotencyKey,
			status, binding, codec, protected)
		if err != nil {
			return store.SecretRotationSchedulePrivacyOuterAcknowledgement{},
				fmt.Errorf("orchestrator: rekey bound scheduler privacy outer: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return store.SecretRotationSchedulePrivacyOuterAcknowledgement{}, fmt.Errorf(
				"%w: bound scheduler privacy outer CAS changed %d rows",
				store.ErrSecretRotationScheduleTickConflict, tag.RowsAffected(),
			)
		}
		return acknowledgement, nil

	case "completed":
		if requirement.TerminalHTTPStatus == 0 || len(requirement.OriginalTerminalBody) == 0 ||
			codec == "" || len(protected) == 0 {
			return store.SecretRotationSchedulePrivacyOuterAcknowledgement{}, fmt.Errorf(
				"%w: completed scheduler privacy outer lacks exact terminal evidence",
				store.ErrSecretRotationScheduleTickConflict,
			)
		}
	default:
		return store.SecretRotationSchedulePrivacyOuterAcknowledgement{}, fmt.Errorf(
			"%w: scheduler privacy outer status %q is unsupported",
			store.ErrSecretRotationScheduleTickConflict, status,
		)
	}

	protectedCAS := append([]byte(nil), protected...)
	defer secret.Wipe(protectedCAS)
	plaintext, err := i.openResult(
		ctx, tenantID, rawIdempotencyKey, binding, codec,
		append([]byte(nil), protected...),
	)
	if err != nil {
		return store.SecretRotationSchedulePrivacyOuterAcknowledgement{}, err
	}
	defer secret.Wipe(plaintext)
	var cached schedulerPrivacyCachedResponse
	if !json.Valid(plaintext) || json.Unmarshal(plaintext, &cached) != nil {
		return store.SecretRotationSchedulePrivacyOuterAcknowledgement{}, fmt.Errorf(
			"%w: protected scheduler response is not a cached HTTP envelope",
			store.ErrSecretRotationScheduleTickConflict,
		)
	}
	defer secret.Wipe(cached.Body)
	if cached.Status != requirement.TerminalHTTPStatus ||
		!crypto.ConstantTimeEqual([]byte(cached.Binding), []byte(binding)) ||
		!bytes.Equal(cached.Body, requirement.OriginalTerminalBody) {
		return store.SecretRotationSchedulePrivacyOuterAcknowledgement{}, fmt.Errorf(
			"%w: protected scheduler response differs from exact terminal tick bytes",
			store.ErrSecretRotationScheduleTickConflict,
		)
	}

	nextPlaintext := plaintext
	var rewritten []byte
	if requirement.TerminalBodyMatch {
		if len(requirement.RewrittenTerminalBody) == 0 ||
			bytes.Equal(requirement.RewrittenTerminalBody, requirement.OriginalTerminalBody) {
			return store.SecretRotationSchedulePrivacyOuterAcknowledgement{}, fmt.Errorf(
				"%w: scheduler privacy terminal rewrite is empty or unchanged",
				store.ErrSecretRotationScheduleTickConflict,
			)
		}
		rewrittenBody := append(json.RawMessage(nil), requirement.RewrittenTerminalBody...)
		defer secret.Wipe(rewrittenBody)
		cached.Body = rewrittenBody
		rewritten, err = json.Marshal(cached)
		if err != nil {
			return store.SecretRotationSchedulePrivacyOuterAcknowledgement{}, err
		}
		defer secret.Wipe(rewritten)
		nextPlaintext = rewritten
	} else if len(requirement.RewrittenTerminalBody) != 0 {
		return store.SecretRotationSchedulePrivacyOuterAcknowledgement{}, fmt.Errorf(
			"%w: scheduler privacy outer supplied an unrequested terminal rewrite",
			store.ErrSecretRotationScheduleTickConflict,
		)
	}

	resolvedCodec, resolvedProtected, err := i.protectResult(
		ctx, tenantID, requirement.ReplacementIdempotencyKey, binding, nextPlaintext,
	)
	if err != nil {
		return store.SecretRotationSchedulePrivacyOuterAcknowledgement{}, err
	}
	tag, err := tx.Exec(ctx,
		`UPDATE idempotency_keys
		    SET key = $3, result_codec = $4, result = $5
		  WHERE tenant_id = $1 AND key = $2
		    AND status = $6 AND request_binding = $7
		    AND result_codec = $8 AND result IS NOT DISTINCT FROM $9`,
		tenantID, rawIdempotencyKey, requirement.ReplacementIdempotencyKey,
		resolvedCodec, resolvedProtected, status, binding, codec, protectedCAS)
	if err != nil {
		secret.Wipe(resolvedProtected)
		return store.SecretRotationSchedulePrivacyOuterAcknowledgement{},
			fmt.Errorf("orchestrator: protect scheduler privacy outer in place: %w", err)
	}
	if tag.RowsAffected() != 1 {
		secret.Wipe(resolvedProtected)
		return store.SecretRotationSchedulePrivacyOuterAcknowledgement{}, fmt.Errorf(
			"%w: completed scheduler privacy outer CAS changed %d rows",
			store.ErrSecretRotationScheduleTickConflict, tag.RowsAffected(),
		)
	}
	acknowledgement.ResolvedResultCodec = resolvedCodec
	acknowledgement.ProtectedResult = resolvedProtected
	return acknowledgement, nil
}

// doProtectedTransactional preserves Do/DoBound's wait-and-replay behavior while
// adding one durable wall for the new failure point introduced by ResultProtector.
// The short first transaction commits a pending row before fn can produce an
// independently durable effect. The execution transaction then locks that row
// for the whole callback, so an identical concurrent caller still waits and
// replays the completed bytes. A callback error deletes the preclaim and remains
// retryable. Once fn succeeds, however, a Protect or completion-store failure
// leaves pending/indeterminate state. A retry returns ErrInProgress for a pending
// wall or ErrEffectIndeterminate for an explicit one; neither path guesses that
// rerunning fn is safe.
func (i *Idempotency) doProtectedTransactional(
	ctx context.Context,
	tenantID, key, binding string,
	fn func(context.Context) ([]byte, error),
) ([]byte, error) {
	releaseFlight, err := i.acquireProtectedFlight(ctx, tenantID, key)
	if err != nil {
		return nil, err
	}
	defer releaseFlight()

	for {
		claimed := false
		err := i.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx,
				`INSERT INTO idempotency_keys (tenant_id, key, status, request_binding)
				 VALUES ($1, $2, 'pending', $3)
				 ON CONFLICT (tenant_id, key) DO NOTHING`,
				tenantID, key, binding)
			if err != nil {
				return fmt.Errorf("orchestrator: preclaim protected idempotency key: %w", err)
			}
			claimed = tag.RowsAffected() == 1
			return nil
		})
		if err != nil {
			return nil, err
		}
		if claimed {
			return i.executeProtectedClaim(ctx, tenantID, key, binding, fn)
		}

		result, codec, retry, err := i.readProtectedClaim(ctx, tenantID, key, binding)
		if retry {
			continue
		}
		if err != nil {
			return nil, err
		}
		return i.openResult(ctx, tenantID, key, binding, codec, result)
	}
}

// readProtectedClaim locks an existing key before deciding its outcome. That row
// lock makes an identical concurrent request wait behind the executing owner,
// matching the original single-transaction behavior. A pending row is never
// auto-promoted: merely acquiring its lock does not prove its owner died or that
// a callback ran. Only the execution owner may write indeterminate after fn has
// actually returned success.
func (i *Idempotency) readProtectedClaim(
	ctx context.Context,
	tenantID, key, binding string,
) (result []byte, codec string, retry bool, err error) {
	var outcome error
	err = i.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var status, storedBinding string
		scanErr := tx.QueryRow(ctx,
			`SELECT status, request_binding
			   FROM idempotency_keys
			  WHERE tenant_id = $1 AND key = $2
			  FOR UPDATE`,
			tenantID, key).Scan(&status, &storedBinding)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			retry = true
			return nil
		}
		if scanErr != nil {
			return fmt.Errorf("orchestrator: lock protected idempotency key: %w", scanErr)
		}
		if !idempotencyBindingEqual(storedBinding, binding) {
			return ErrIdempotencyConflict
		}
		switch status {
		case "completed":
			if scanErr := tx.QueryRow(ctx,
				`SELECT result_codec, result
				   FROM idempotency_keys
				  WHERE tenant_id = $1 AND key = $2 AND request_binding = $3`,
				tenantID, key, binding).Scan(&codec, &result); scanErr != nil {
				return fmt.Errorf("orchestrator: load protected idempotency result: %w", scanErr)
			}
		case "pending":
			outcome = ErrInProgress
		case "indeterminate":
			outcome = ErrEffectIndeterminate
		default:
			outcome = ErrInProgress
		}
		return nil
	})
	if err != nil {
		secret.Wipe(result)
		return nil, "", false, err
	}
	if outcome != nil {
		secret.Wipe(result)
		return nil, "", false, outcome
	}
	return result, codec, retry, nil
}

func (i *Idempotency) executeProtectedClaim(
	ctx context.Context,
	tenantID, key, binding string,
	fn func(context.Context) ([]byte, error),
) ([]byte, error) {
	var (
		result            []byte
		resultCodec       string
		replayed          bool
		callbackErr       error
		postSuccessErr    error
		callbackSucceeded bool
	)
	defer func() { secret.Wipe(result) }()

	err := i.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var status, storedBinding string
		scanErr := tx.QueryRow(ctx,
			`SELECT status, request_binding
			   FROM idempotency_keys
			  WHERE tenant_id = $1 AND key = $2
			  FOR UPDATE`,
			tenantID, key).Scan(&status, &storedBinding)
		if scanErr != nil {
			return fmt.Errorf("orchestrator: lock owned protected idempotency key: %w", scanErr)
		}
		if !idempotencyBindingEqual(storedBinding, binding) {
			return ErrIdempotencyConflict
		}
		switch status {
		case "completed":
			if scanErr := tx.QueryRow(ctx,
				`SELECT result_codec, result
				   FROM idempotency_keys
				  WHERE tenant_id = $1 AND key = $2 AND request_binding = $3`,
				tenantID, key, binding).Scan(&resultCodec, &result); scanErr != nil {
				return fmt.Errorf("orchestrator: load raced protected idempotency result: %w", scanErr)
			}
			replayed = true
			return nil
		case "indeterminate":
			return ErrEffectIndeterminate
		case "pending":
			// This caller inserted the preclaim and owns execution.
		default:
			return ErrInProgress
		}

		out, fnErr := fn(ctx)
		defer secret.Wipe(out)
		if fnErr != nil {
			callbackErr = fnErr
			tag, deleteErr := tx.Exec(ctx,
				`DELETE FROM idempotency_keys
				  WHERE tenant_id = $1 AND key = $2
				    AND request_binding = $3 AND status = 'pending'`,
				tenantID, key, binding)
			if deleteErr != nil {
				return fmt.Errorf("orchestrator: release failed protected callback claim: %w", deleteErr)
			}
			if tag.RowsAffected() != 1 {
				return errors.New("orchestrator: failed protected callback claim changed while locked")
			}
			return nil
		}
		callbackSucceeded = true

		codec, protected, protectErr := i.protectResult(ctx, tenantID, key, binding, out)
		if protectErr != nil {
			postSuccessErr = protectErr
			tag, updateErr := tx.Exec(ctx,
				`UPDATE idempotency_keys
				    SET status = 'indeterminate'
				  WHERE tenant_id = $1 AND key = $2
				    AND request_binding = $3 AND status = 'pending'`,
				tenantID, key, binding)
			if updateErr != nil {
				return fmt.Errorf("orchestrator: persist protection failure wall: %w", updateErr)
			}
			if tag.RowsAffected() != 1 {
				return errors.New("orchestrator: protection failure claim changed while locked")
			}
			return nil
		}
		defer secret.Wipe(protected)

		tag, updateErr := tx.Exec(ctx,
			`UPDATE idempotency_keys
			    SET status = 'completed', result_codec = $4, result = $5, completed_at = now()
			  WHERE tenant_id = $1 AND key = $2
			    AND request_binding = $3 AND status = 'pending'`,
			tenantID, key, binding, codec, protected)
		if updateErr != nil {
			return fmt.Errorf("orchestrator: record protected idempotency result: %w", updateErr)
		}
		if tag.RowsAffected() != 1 {
			return errors.New("orchestrator: protected idempotency claim changed while locked")
		}
		result = append([]byte(nil), out...)
		return nil
	})

	if callbackErr != nil {
		if err != nil {
			return nil, fmt.Errorf("%w (release protected callback claim: %v)", callbackErr, err)
		}
		return nil, callbackErr
	}
	if postSuccessErr != nil {
		if err != nil {
			postSuccessErr = errors.Join(postSuccessErr, err)
			if markErr := i.markProtectedIndeterminate(ctx, tenantID, key, binding); markErr != nil {
				postSuccessErr = errors.Join(postSuccessErr, markErr)
			}
		}
		return nil, protectedIndeterminateError(postSuccessErr)
	}
	if err != nil {
		if callbackSucceeded {
			if markErr := i.markProtectedIndeterminate(ctx, tenantID, key, binding); markErr != nil {
				err = errors.Join(err, markErr)
			}
			return nil, protectedIndeterminateError(err)
		}
		return nil, err
	}
	if replayed {
		return i.openResult(ctx, tenantID, key, binding, resultCodec, result)
	}
	return append([]byte(nil), result...), nil
}

func (i *Idempotency) markProtectedIndeterminate(ctx context.Context, tenantID, key, binding string) error {
	repairCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return i.store.WithTenant(repairCtx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(repairCtx,
			`UPDATE idempotency_keys
			    SET status = 'indeterminate'
			  WHERE tenant_id = $1 AND key = $2
			    AND request_binding = $3 AND status = 'pending'`,
			tenantID, key, binding)
		if err != nil {
			return fmt.Errorf("orchestrator: persist indeterminate protected result: %w", err)
		}
		if tag.RowsAffected() == 1 {
			return nil
		}

		// A lost COMMIT response can mean the completed/indeterminate write
		// actually committed. Prove that durable wall before treating zero updated
		// rows as success; a missing or rebound claim is not a safe outcome.
		var status, storedBinding string
		if err := tx.QueryRow(repairCtx,
			`SELECT status, request_binding
			   FROM idempotency_keys
			  WHERE tenant_id = $1 AND key = $2`,
			tenantID, key).Scan(&status, &storedBinding); err != nil {
			return fmt.Errorf("orchestrator: verify protected result failure wall: %w", err)
		}
		if !idempotencyBindingEqual(storedBinding, binding) {
			return ErrIdempotencyConflict
		}
		if status != "completed" && status != "indeterminate" {
			return fmt.Errorf("orchestrator: protected result failure left unsafe status %q", status)
		}
		return nil
	})
}

func protectedIndeterminateError(cause error) error {
	if cause == nil {
		return ErrEffectIndeterminate
	}
	return fmt.Errorf("%w: %w", ErrEffectIndeterminate, cause)
}

func idempotencyBindingEqual(stored, supplied string) bool {
	if stored == "" || supplied == "" {
		return stored == supplied
	}
	return crypto.ConstantTimeEqual([]byte(stored), []byte(supplied))
}

// acquireProtectedFlight closes the preclaim→execution gap for callers sharing
// this Idempotency instance. PostgreSQL remains the cross-process authority: a
// different process that reaches a committed pending row fails safely with
// ErrInProgress rather than inferring that the owner is dead.
func (i *Idempotency) acquireProtectedFlight(ctx context.Context, tenantID, key string) (func(), error) {
	flightKey := tenantID + "\x00" + key
	for {
		i.protectedFlightMu.Lock()
		if i.protectedFlights == nil {
			i.protectedFlights = make(map[string]chan struct{})
		}
		if wait, exists := i.protectedFlights[flightKey]; exists {
			i.protectedFlightMu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		done := make(chan struct{})
		i.protectedFlights[flightKey] = done
		i.protectedFlightMu.Unlock()
		return func() {
			i.protectedFlightMu.Lock()
			if current, exists := i.protectedFlights[flightKey]; exists && current == done {
				delete(i.protectedFlights, flightKey)
				close(done)
			}
			i.protectedFlightMu.Unlock()
		}, nil
	}
}

func incompleteResultError(status string) error {
	if status == "indeterminate" {
		return ErrEffectIndeterminate
	}
	return ErrInProgress
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
// With a configured ResultProtector, a short committed preclaim is added before
// fn; post-success protection/storage failures then remain non-replayable and
// return ErrEffectIndeterminate.
func (i *Idempotency) Do(ctx context.Context, tenantID, key string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
	if i == nil {
		return nil, errors.New("orchestrator: idempotency store is not configured")
	}
	if i.memory != nil {
		return i.doBoundMemory(ctx, tenantID, key, "", false, true, fn)
	}
	if i.store == nil {
		return nil, errors.New("orchestrator: idempotency store is not configured")
	}
	if i.resultProtector != nil {
		return i.doProtectedTransactional(ctx, tenantID, key, "", fn)
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
				return incompleteResultError(status)
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
// LookupBound returns the recorded result of a COMPLETED bound operation
// without claiming, creating, or waiting on anything. It exists for callers
// that derive time-bucketed keys and must consult the PREVIOUS bucket before
// executing under the current one (AUD-201 follow-up I3/V9): a byte-identical
// retry that straddles a bucket boundary would otherwise claim a fresh row and
// re-run the mutation. In-flight and indeterminate claims report not-found —
// the caller then proceeds under its current key, and the underlying claim
// machinery keeps its own guarantees.
func (i *Idempotency) LookupBound(ctx context.Context, tenantID, key, binding string) ([]byte, bool, error) {
	if i == nil || tenantID == "" || key == "" || binding == "" {
		return nil, false, nil
	}
	if i.memory != nil {
		i.memoryMu.Lock()
		record, exists := i.boundMemory[tenantID+"\x00"+key]
		var out []byte
		found := false
		if exists && record.completed && idempotencyBindingEqual(record.binding, binding) {
			out = append([]byte(nil), record.result...)
			found = true
		}
		i.memoryMu.Unlock()
		return out, found, nil
	}
	if i.store == nil {
		return nil, false, nil
	}
	var (
		result []byte
		codec  string
		found  bool
	)
	err := i.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		scanErr := tx.QueryRow(ctx,
			`SELECT result_codec, result
			   FROM idempotency_keys
			  WHERE tenant_id = $1 AND key = $2 AND request_binding = $3 AND status = 'completed'`,
			tenantID, key, binding).Scan(&codec, &result)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return nil
		}
		if scanErr != nil {
			return fmt.Errorf("orchestrator: look up bound idempotency result: %w", scanErr)
		}
		found = true
		return nil
	})
	if err != nil || !found {
		secret.Wipe(result)
		return nil, false, err
	}
	if i.resultProtector != nil {
		plaintext, openErr := i.openResult(ctx, tenantID, key, binding, codec, result)
		secret.Wipe(result)
		if openErr != nil {
			return nil, false, openErr
		}
		return plaintext, true, nil
	}
	return result, true, nil
}

func (i *Idempotency) DoBound(ctx context.Context, tenantID, key, binding string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
	if i == nil {
		return nil, errors.New("orchestrator: idempotency store is not configured")
	}
	if tenantID == "" || key == "" || binding == "" {
		return nil, errors.New("orchestrator: bound idempotency requires tenant, key, and request binding")
	}
	if i.memory != nil {
		return i.doBoundMemory(ctx, tenantID, key, binding, false, true, fn)
	}
	if i.store == nil {
		return nil, errors.New("orchestrator: idempotency store is not configured")
	}
	if i.resultProtector != nil {
		return i.doProtectedTransactional(ctx, tenantID, key, binding, fn)
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
			if !idempotencyBindingEqual(storedBinding, binding) {
				return ErrIdempotencyConflict
			}
			if status != "completed" {
				return incompleteResultError(status)
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

// TenantRegistrationIdempotencyClaim is the first phase of the one specialized
// two-phase registration recorder. ProtectedResult ownership transfers to the
// caller, which must wipe it after opening or abandoning it.
type TenantRegistrationIdempotencyClaim struct {
	Created         bool
	Completed       bool
	EventID         string
	EventTime       time.Time
	ResultCodec     string
	ProtectedResult []byte
}

const tenantRegistrationAnchorPrefix = "trstctl-tenant-registration-anchor-v1\x00tenant-registration-"

func tenantRegistrationAnchor(eventID string) ([]byte, error) {
	const eventPrefix = "tenant-registration-"
	if !strings.HasPrefix(eventID, eventPrefix) {
		return nil, errors.New("orchestrator: tenant registration event id has the wrong prefix")
	}
	if _, err := uuid.Parse(strings.TrimPrefix(eventID, eventPrefix)); err != nil {
		return nil, errors.New("orchestrator: tenant registration event id is malformed")
	}
	return []byte("trstctl-tenant-registration-anchor-v1\x00" + eventID), nil
}

func parseTenantRegistrationAnchor(raw []byte) (string, error) {
	if !bytes.HasPrefix(raw, []byte(tenantRegistrationAnchorPrefix)) {
		return "", errors.New("orchestrator: pending registration anchor has the wrong format")
	}
	eventID := string(raw[len("trstctl-tenant-registration-anchor-v1\x00"):])
	canonical, err := tenantRegistrationAnchor(eventID)
	if err != nil || !bytes.Equal(canonical, raw) {
		return "", errors.New("orchestrator: pending registration anchor is malformed")
	}
	return eventID, nil
}

// PrepareTenantRegistrationTx commits the non-PII producer identity before an
// event can be appended. The lifecycle advisory lock held by the caller makes
// this row the single durable first-writer fence for a missing tenant UUID. A
// pending retry gets the same event ID and PostgreSQL timestamp; it may then do
// the exceptional retained-history recovery lookup without making that scan the
// normal registration path.
func (i *Idempotency) PrepareTenantRegistrationTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, key, binding, candidateEventID string,
) (TenantRegistrationIdempotencyClaim, error) {
	if i == nil || i.store == nil || tx == nil {
		return TenantRegistrationIdempotencyClaim{}, errors.New("orchestrator: transactional idempotency store is not configured")
	}
	if tenantID == "" || key == "" || binding == "" || candidateEventID == "" {
		return TenantRegistrationIdempotencyClaim{}, errors.New("orchestrator: transactional registration idempotency is incomplete")
	}
	anchor, err := tenantRegistrationAnchor(candidateEventID)
	if err != nil {
		return TenantRegistrationIdempotencyClaim{}, err
	}
	defer secret.Wipe(anchor)

	// Reject a different-key preclaim before it can publish. Generic pending
	// idempotency results are excluded by the exact format prefix and are never
	// opened or interpreted as registration output.
	rows, err := tx.Query(ctx, `
		SELECT key, result
		  FROM idempotency_keys
		 WHERE tenant_id = $1 AND status = 'pending' AND result_codec = $2
		   AND substring(result FROM 1 FOR $3) = $4
		 ORDER BY key
		 FOR UPDATE`, tenantID, ResultCodecRawV0,
		len(tenantRegistrationAnchorPrefix), []byte(tenantRegistrationAnchorPrefix))
	if err != nil {
		return TenantRegistrationIdempotencyClaim{}, fmt.Errorf("orchestrator: inspect pending registration anchors: %w", err)
	}
	for rows.Next() {
		var otherKey string
		var raw []byte
		if err := rows.Scan(&otherKey, &raw); err != nil {
			rows.Close()
			secret.Wipe(raw)
			return TenantRegistrationIdempotencyClaim{}, fmt.Errorf("orchestrator: scan pending registration anchor: %w", err)
		}
		_, parseErr := parseTenantRegistrationAnchor(raw)
		secret.Wipe(raw)
		if parseErr != nil {
			rows.Close()
			return TenantRegistrationIdempotencyClaim{}, parseErr
		}
		if otherKey != key {
			rows.Close()
			return TenantRegistrationIdempotencyClaim{}, ErrInProgress
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return TenantRegistrationIdempotencyClaim{}, fmt.Errorf("orchestrator: iterate pending registration anchors: %w", err)
	}
	rows.Close()

	var createdAt time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO idempotency_keys
		       (tenant_id, key, status, request_binding, result_codec, result, created_at)
		VALUES ($1, $2, 'pending', $3, $4, $5, clock_timestamp())
		ON CONFLICT (tenant_id, key) DO NOTHING
		RETURNING created_at`, tenantID, key, binding, ResultCodecRawV0, anchor).Scan(&createdAt)
	if err == nil {
		return TenantRegistrationIdempotencyClaim{
			Created: true, EventID: candidateEventID, EventTime: createdAt.UTC(),
		}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return TenantRegistrationIdempotencyClaim{}, fmt.Errorf("orchestrator: prepare transactional registration key: %w", err)
	}

	var status, storedBinding, resultCodec string
	var storedResult []byte
	if err := tx.QueryRow(ctx, `
		SELECT status, request_binding, result_codec, result, created_at
		  FROM idempotency_keys
		 WHERE tenant_id = $1 AND key = $2
		 FOR UPDATE`, tenantID, key).Scan(
		&status, &storedBinding, &resultCodec, &storedResult, &createdAt); err != nil {
		return TenantRegistrationIdempotencyClaim{}, fmt.Errorf("orchestrator: load transactional registration binding: %w", err)
	}
	if !idempotencyBindingEqual(storedBinding, binding) {
		secret.Wipe(storedResult)
		return TenantRegistrationIdempotencyClaim{}, ErrIdempotencyConflict
	}
	switch status {
	case "pending":
		defer secret.Wipe(storedResult)
		if resultCodec != ResultCodecRawV0 {
			return TenantRegistrationIdempotencyClaim{}, ErrIdempotencyConflict
		}
		eventID, err := parseTenantRegistrationAnchor(storedResult)
		if err != nil || createdAt.IsZero() {
			return TenantRegistrationIdempotencyClaim{}, ErrIdempotencyConflict
		}
		return TenantRegistrationIdempotencyClaim{
			EventID: eventID, EventTime: createdAt.UTC(),
		}, nil
	case "completed":
		return TenantRegistrationIdempotencyClaim{
			Completed: true, ResultCodec: resultCodec,
			ProtectedResult: storedResult,
		}, nil
	default:
		secret.Wipe(storedResult)
		return TenantRegistrationIdempotencyClaim{}, incompleteResultError(status)
	}
}

// doBoundMemory is the in-process model shared by transactional and durable
// bound calls. It owns cached result bytes and makes identical concurrent calls
// wait for one callback. Transactional claims disappear on callback failure,
// matching a rolled-back DoBound transaction. A protected transactional claim
// becomes indeterminate when Protect fails after callback success. Durable
// claims persist so only an identical retry may reconcile an independently
// durable receiver.
func (i *Idempotency) doBoundMemory(
	ctx context.Context,
	tenantID, key, binding string,
	persist, wallProtectFailure bool,
	fn func(context.Context) ([]byte, error),
) ([]byte, error) {
	memoryKey := tenantID + "\x00" + key
	for {
		created := false
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
			if !idempotencyBindingEqual(record.binding, binding) {
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
			if record.indeterminate {
				i.memoryMu.Unlock()
				return nil, ErrEffectIndeterminate
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
			created = true
		}
		i.memoryMu.Unlock()

		out, err := fn(ctx)
		callbackSucceeded := err == nil
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
		} else if callbackSucceeded && wallProtectFailure {
			record.indeterminate = true
		} else if !callbackSucceeded && created && record.persist && errors.Is(err, ErrIdempotencyConflict) {
			// A durable receiver may reveal that a fresh cache claim belongs to
			// the wrong canonical command after generic idempotency GC. That
			// conflict proves this newly-created claim has no effect to recover.
			// Remove only this call's still-uncompleted claim so the original
			// command can recover from the receiver; every other durable failure
			// remains bound for reconciliation.
			delete(i.boundMemory, memoryKey)
		} else if !record.persist {
			delete(i.boundMemory, memoryKey)
		}
		close(record.wait)
		i.memoryMu.Unlock()
		secret.Wipe(protected)
		if err != nil {
			secret.Wipe(out)
			if callbackSucceeded && wallProtectFailure {
				return nil, protectedIndeterminateError(err)
			}
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
		return i.doBoundMemory(ctx, tenantID, key, "", false, false, fn)
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
			return incompleteResultError(status)
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
		return i.doBoundMemory(ctx, tenantID, key, binding, true, false, fn)
	}
	if i.store == nil {
		return nil, errors.New("orchestrator: idempotency store is not configured")
	}

	var (
		completed    bool
		claimed      bool
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
			claimed = true
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
		if !idempotencyBindingEqual(storedBinding, binding) {
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
		case "indeterminate":
			return ErrEffectIndeterminate
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
		if claimed && errors.Is(err, ErrIdempotencyConflict) {
			cleanupErr := i.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
				if _, deleteErr := tx.Exec(ctx,
					`DELETE FROM idempotency_keys
					  WHERE tenant_id = $1 AND key = $2
					    AND request_binding = $3 AND status = 'bound'`,
					tenantID, key, binding); deleteErr != nil {
					return fmt.Errorf("orchestrator: release conflicting bound durable key: %w", deleteErr)
				}
				return nil
			})
			if cleanupErr != nil {
				return nil, errors.Join(err, cleanupErr)
			}
		}
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
		if !idempotencyBindingEqual(storedBinding, binding) {
			return ErrIdempotencyConflict
		}
		if status != "completed" {
			return incompleteResultError(status)
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

// PreparedDurableEffectClaim is returned by a receiver-specific preparation
// callback. CompletedResult remains protected and opaque until this package
// checks the binding and opens it through the configured result protector.
type PreparedDurableEffectClaim struct {
	Completed       bool
	ResultCodec     string
	CompletedResult []byte
}

// DoPreparedDurableEffectBound is the strict durable path for a receiver whose
// immutable work set must commit in the same transaction as the outer bind.
// prepare owns that bind and receiver snapshot under repeatable-read. After fn
// terminalizes the receiver and releases external resources, verifyTerminal
// proves the plaintext result against that receiver in the same short
// transaction that protects and completes the outer cache row.
func (i *Idempotency) DoPreparedDurableEffectBound(
	ctx context.Context,
	tenantID, key, binding string,
	prepare func(context.Context, pgx.Tx) (PreparedDurableEffectClaim, error),
	verifyTerminal func(context.Context, pgx.Tx, []byte) error,
	fn func(context.Context) ([]byte, error),
) ([]byte, error) {
	if i == nil || i.store == nil {
		return nil, errors.New("orchestrator: prepared durable idempotency requires PostgreSQL")
	}
	if tenantID == "" || key == "" || binding == "" || prepare == nil || verifyTerminal == nil || fn == nil {
		return nil, errors.New("orchestrator: prepared durable idempotency requires exact identity and callbacks")
	}

	var claim PreparedDurableEffectClaim
	err := i.store.WithPrivacyTenantProjectionRepeatableRead(
		ctx, tenantID, "secret rotation scheduler aggregate prepare", func(tx pgx.Tx) error {
			var err error
			claim, err = prepare(ctx, tx)
			return err
		})
	defer secret.Wipe(claim.CompletedResult)
	if err != nil {
		return nil, err
	}
	if claim.Completed {
		if claim.ResultCodec == "" || len(claim.CompletedResult) == 0 {
			return nil, errors.New("orchestrator: completed prepared durable claim has no protected result")
		}
		opened, err := i.openResult(ctx, tenantID, key, binding, claim.ResultCodec, claim.CompletedResult)
		if err != nil {
			return nil, err
		}
		// A restored or pre-fix completed outer row is not proof by itself. Re-run
		// the receiver verifier over the opened bytes so replay must still match
		// the exact terminal receiver state and its current closed schema.
		if err := i.store.WithPrivacyTenantProjectionRepeatableRead(
			ctx, tenantID, "completed prepared durable result verification", func(tx pgx.Tx) error {
				return verifyTerminal(ctx, tx, opened)
			},
		); err != nil {
			secret.Wipe(opened)
			return nil, err
		}
		return opened, nil
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

	var (
		storedResult []byte
		storedCodec  string
		usedStored   bool
	)
	defer secret.Wipe(storedResult)
	err = i.store.WithPrivacyTenantProjectionRepeatableRead(
		ctx, tenantID, "secret rotation scheduler aggregate completion", func(tx pgx.Tx) error {
			if err := verifyTerminal(ctx, tx, out); err != nil {
				return err
			}
			tag, err := tx.Exec(ctx,
				`UPDATE idempotency_keys
			    SET status = 'completed', result_codec = $4, result = $5,
			        completed_at = clock_timestamp()
			  WHERE tenant_id = $1 AND key = $2
			    AND status = 'bound' AND request_binding = $3`,
				tenantID, key, binding, codec, protected)
			if err != nil {
				return fmt.Errorf("orchestrator: complete prepared durable key: %w", err)
			}
			if tag.RowsAffected() == 1 {
				return nil
			}
			var status, storedBinding string
			if err := tx.QueryRow(ctx,
				`SELECT status, request_binding
			   FROM idempotency_keys
			  WHERE tenant_id = $1 AND key = $2
			  FOR UPDATE`, tenantID, key).Scan(&status, &storedBinding); err != nil {
				return fmt.Errorf("orchestrator: load prepared durable completion: %w", err)
			}
			if !idempotencyBindingEqual(storedBinding, binding) {
				return ErrIdempotencyConflict
			}
			if status != "completed" {
				return incompleteResultError(status)
			}
			if err := tx.QueryRow(ctx,
				`SELECT result_codec, result
			   FROM idempotency_keys
			  WHERE tenant_id = $1 AND key = $2 AND request_binding = $3`,
				tenantID, key, binding).Scan(&storedCodec, &storedResult); err != nil {
				return fmt.Errorf("orchestrator: load prepared durable result: %w", err)
			}
			usedStored = true
			return nil
		})
	if err != nil {
		return nil, err
	}
	if usedStored {
		return i.openResult(ctx, tenantID, key, binding, storedCodec, storedResult)
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
			if record.indeterminate {
				i.memoryMu.Unlock()
				return nil, ErrEffectIndeterminate
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
			return incompleteResultError(status)
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

// BoundResultCompleted proves that one authenticated durable result reached the
// completed wall without selecting or opening its protected bytes. Internal
// workers use this before an effect (such as tenant seal) that intentionally
// makes the tenant result key unavailable. A mismatched binding is rejected
// before any result column is selected.
func (i *Idempotency) BoundResultCompleted(
	ctx context.Context,
	tenantID, key, binding string,
) (bool, error) {
	if i == nil || tenantID == "" || key == "" || binding == "" {
		return false, errors.New("orchestrator: bound completion check requires tenant, key, and request binding")
	}
	if i.memory != nil {
		memoryKey := tenantID + "\x00" + key
		i.memoryMu.Lock()
		record, ok := i.boundMemory[memoryKey]
		if !ok {
			i.memoryMu.Unlock()
			return false, ErrIdempotencyNotFound
		}
		if !idempotencyBindingEqual(record.binding, binding) {
			i.memoryMu.Unlock()
			return false, ErrIdempotencyConflict
		}
		if record.indeterminate {
			i.memoryMu.Unlock()
			return false, ErrEffectIndeterminate
		}
		completed := record.completed
		i.memoryMu.Unlock()
		if !completed {
			return false, ErrInProgress
		}
		return true, nil
	}
	if i.store == nil {
		return false, errors.New("orchestrator: idempotency store is not configured")
	}
	var status, storedBinding string
	err := i.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`SELECT status, request_binding
			   FROM idempotency_keys
			  WHERE tenant_id = $1 AND key = $2`,
			tenantID, key).Scan(&status, &storedBinding)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrIdempotencyNotFound
		}
		if err != nil {
			return fmt.Errorf("orchestrator: load bound completion wall: %w", err)
		}
		if storedBinding == "" || !idempotencyBindingEqual(storedBinding, binding) {
			return ErrIdempotencyConflict
		}
		if status != "completed" {
			return incompleteResultError(status)
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return true, nil
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
		if !idempotencyBindingEqual(record.binding, binding) {
			i.memoryMu.Unlock()
			return nil, ErrIdempotencyConflict
		}
		if record.indeterminate {
			i.memoryMu.Unlock()
			return nil, ErrEffectIndeterminate
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
		if storedBinding == "" || !idempotencyBindingEqual(storedBinding, binding) {
			return ErrIdempotencyConflict
		}
		if status != "completed" {
			return incompleteResultError(status)
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
