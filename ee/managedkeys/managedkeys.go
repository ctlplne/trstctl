// Package managedkeys is the served BYOK/HSM managed-key lifecycle (CRYPTO-005 /
// EXC-CRYPTO-01). The crypto.RemoteKeyLifecycle primitives — generate, rotate,
// revoke, zeroize for a key whose private material lives in a cloud KMS or a
// networked HSM and never enters this process — were previously library-tier:
// implemented and tested (internal/kms/*) but reachable from no served route. This
// package is the control-plane service that drives them on behalf of an
// authenticated operator, so the running binary, not just a test, manages a
// remote-custody key's lifecycle.
//
// Every operation is:
//   - tenant-scoped (AN-1): the tenant is taken from the authenticated request and
//     stamped on the event and the in-memory record; nothing is global;
//   - event-sourced (AN-2): each transition emits a key-material-free
//     byok.LifecycleEvent through an injected sink, so the key history rebuilds from
//     the log exactly like the in-process byok path. The private key is NEVER in the
//     payload (for a remote key it is never even in this address space);
//   - idempotent (AN-5): a replay of the same Idempotency-Key returns the original
//     result without performing the provider operation again;
//   - dual-controlled (AN-4 spirit / four-eyes): the destructive transitions on
//     CA/KEK-class material (rotate, revoke, zeroize) require a recorded approval by
//     a principal DISTINCT from the requester before the provider is called. The
//     gate reuses the same distinct-approver contract the served issuance gate uses
//     (internal/api MutationGate / ApprovalChecker).
//
// The package depends only on the crypto boundary (crypto.RemoteKeyLifecycle,
// crypto.KeyRef, crypto.Algorithm) and the byok event vocabulary; it imports no
// crypto/* and holds no private key material itself.
package managedkeys

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/byok"
)

// Lifecycle is the remote-custody key lifecycle the service drives. It is exactly
// crypto.RemoteKeyLifecycle; every internal/kms backend that implements it (AWS
// KMS today, plus the in-memory fake used by the served E2E test) plugs in here.
type Lifecycle = crypto.RemoteKeyLifecycle

// EventSink records a lifecycle transition (AN-2). The served control plane backs
// it with the event log; tests back it in memory. It is the same sink the
// in-process byok lifecycle emits through, so the two paths share one event
// vocabulary and one projection.
type EventSink = byok.EventSink

// ApprovalGate reports whether a destructive managed-key transition has a recorded
// approval by a principal DISTINCT from the requester (dual control). It mirrors the
// served issuance gate's ApprovalChecker contract so the same event-store-backed
// implementation satisfies both. A nil gate disables dual control (single-operator
// mode); a configured gate is fail-closed — an unapproved or self-approved request
// is refused before the provider is ever called.
type ApprovalGate interface {
	// IsApproved reports whether the (tenant, key, action) destructive action has a
	// distinct-approver approval on record. action is one of ActionRotate,
	// ActionRevoke, ActionZeroize; requester is the principal driving the request and
	// never counts as their own approver. reason is a human-readable denial cause.
	IsApproved(ctx context.Context, tenantID, keyID, action, requester string) (approved bool, reason string)
}

// Idempotency records a mutation result under (tenant, key) so a replay returns the
// original outcome without re-running the provider operation (AN-5). The served
// control plane backs it with the orchestrator's durable recorder; tests back it in
// memory. When nil, the service still works but is not replay-safe (used only where
// the caller guarantees single delivery).
type Idempotency interface {
	// Do runs fn at most once per (tenantID, key) and returns the result fn produced
	// (or the cached result of the first run). An empty key means "do not dedupe".
	Do(ctx context.Context, tenantID, key string, fn func(context.Context) (Result, error)) (Result, error)
}

// Destructive-action names. They are the policy/approval action strings the gate
// checks, distinct from the read-only generate (which mints new material and needs
// no prior approval — there is nothing yet to destroy).
const (
	ActionGenerate = "managedkey:generate"
	ActionRotate   = "managedkey:rotate"
	ActionRevoke   = "managedkey:revoke"
	ActionZeroize  = "managedkey:zeroize"
)

// Errors the service returns.
var (
	// ErrTenantRequired is returned when a tenant id is missing (AN-1).
	ErrTenantRequired = errors.New("managedkeys: tenant id is required")
	// ErrKeyRefRequired is returned when a lifecycle op is missing its key ref.
	ErrKeyRefRequired = api.ErrManagedKeyRefRequired
	// ErrNotApproved is returned when dual control is on and the destructive action
	// lacks a distinct-approver approval. It is fail-closed: the provider is not
	// called.
	ErrNotApproved = api.ErrManagedKeyNotApproved
	// ErrUnknownKey is returned for an operation on a key this service did not mint.
	ErrUnknownKey = api.ErrManagedKeyUnknown
)

// Result is the public outcome of a lifecycle operation. It carries only
// non-secret metadata (the key id, algorithm, current version, and PKIX public
// key); the private material never appears here, and for a remote key never enters
// this process at all.
type Result = api.ManagedKey

// record is the service's tenant-scoped in-memory bookkeeping for a managed key.
// It tracks the current provider handle, version, and state so rotate/revoke/
// zeroize can target the right material and so a replay can be answered. It holds
// NO private bytes.
type record struct {
	ref     crypto.KeyRef
	version int
	state   byok.State
	pub     crypto.PublicKey
}

// Service is the served managed-key lifecycle. Construct it with New.
type Service struct {
	backend Lifecycle
	sink    EventSink
	gate    ApprovalGate
	idem    Idempotency
	clock   func() time.Time

	mu   sync.Mutex
	keys map[string]*record // key: tenantID + "\x00" + keyID
}

// Config configures a Service.
type Config struct {
	// Backend is the remote-custody lifecycle backend (a KMS/HSM). Required.
	Backend Lifecycle
	// Sink receives the AN-2 lifecycle events. Required (a dropped event would make
	// the key history unrebuildable, so the service fails closed on emit error).
	Sink EventSink
	// Gate enforces dual control on destructive transitions. Nil disables it.
	Gate ApprovalGate
	// Idem makes operations replay-safe (AN-5). Nil disables deduping.
	Idem Idempotency
	// Clock is injectable for tests.
	Clock func() time.Time
}

// New validates configuration and constructs a Service.
func New(cfg Config) (*Service, error) {
	if cfg.Backend == nil {
		return nil, fmt.Errorf("managedkeys: a RemoteKeyLifecycle backend is required")
	}
	if cfg.Sink == nil {
		return nil, fmt.Errorf("managedkeys: an event sink is required (AN-2)")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Service{
		backend: cfg.Backend,
		sink:    cfg.Sink,
		gate:    cfg.Gate,
		idem:    cfg.Idem,
		clock:   cfg.Clock,
		keys:    map[string]*record{},
	}, nil
}

func mapKey(tenantID, keyID string) string { return tenantID + "\x00" + keyID }

// Generate mints a new managed key of alg in the backend (the private material is
// born in the provider) and records it under the tenant. It emits
// byok.EventKeyGenerated (AN-2). Generation creates new material, so it requires no
// prior approval. It is idempotent on idempotencyKey.
func (s *Service) Generate(ctx context.Context, tenantID string, alg crypto.Algorithm, idempotencyKey string) (Result, error) {
	if tenantID == "" {
		return Result{}, ErrTenantRequired
	}
	return s.dedupe(ctx, tenantID, idempotencyKey, func(ctx context.Context) (Result, error) {
		signer, ref, err := s.backend.GenerateManagedKey(ctx, alg)
		if err != nil {
			return Result{}, fmt.Errorf("managedkeys: generate: %w", err)
		}
		pub := signer.Public()
		rec := &record{ref: ref, version: 1, state: byok.StateActive, pub: pub}
		// Emit BEFORE recording locally so a dropped event leaves no orphan record
		// (AN-2 is the source of truth, same discipline as the byok/secretstore path).
		if err := s.emit(ctx, byok.EventKeyGenerated, tenantID, rec, byok.OriginGenerated, 0); err != nil {
			return Result{}, err
		}
		s.mu.Lock()
		s.keys[mapKey(tenantID, ref.ID)] = rec
		s.mu.Unlock()
		return resultOf(rec), nil
	})
}

// Rotate mints a successor key in the backend and re-points the managed record at
// it (supersede-then-retire: the prior key is left intact for the operator to
// revoke/zeroize once issuance is re-pointed). Rotate is destructive of the current
// generation's authority, so it requires a distinct-approver approval when dual
// control is on. It emits byok.EventKeyRotated (AN-2) carrying the superseded
// version in Replaces.
func (s *Service) Rotate(ctx context.Context, tenantID, keyID, requester, idempotencyKey string) (Result, error) {
	return s.destructive(ctx, tenantID, keyID, requester, idempotencyKey, ActionRotate, byok.EventKeyRotated,
		func(ctx context.Context, rec *record) error {
			signer, newRef, err := s.backend.RotateKey(ctx, rec.ref)
			if err != nil {
				return fmt.Errorf("managedkeys: rotate: %w", err)
			}
			rec.ref = newRef
			rec.version++
			rec.pub = signer.Public()
			rec.state = byok.StateActive
			return nil
		})
}

// Revoke disables the key in the backend (the provider refuses further signatures —
// fail-closed at the device) and marks the record revoked. It is reversible at the
// provider until zeroized, mirroring the in-process revoked-then-zeroized two-step.
// It requires a distinct-approver approval under dual control and emits
// byok.EventKeyRevoked (AN-2).
func (s *Service) Revoke(ctx context.Context, tenantID, keyID, requester, idempotencyKey string) (Result, error) {
	return s.destructive(ctx, tenantID, keyID, requester, idempotencyKey, ActionRevoke, byok.EventKeyRevoked,
		func(ctx context.Context, rec *record) error {
			if err := s.backend.RevokeKey(ctx, rec.ref); err != nil {
				return fmt.Errorf("managedkeys: revoke: %w", err)
			}
			rec.state = byok.StateRevoked
			return nil
		})
}

// Zeroize schedules/performs the provider's destruction of the key material (the
// remote analogue of wiping a locked buffer). After zeroize the operator can no
// longer recover the material once the provider's window elapses. It is the most
// destructive transition and requires a distinct-approver approval under dual
// control; it emits byok.EventKeyZeroized (AN-2).
func (s *Service) Zeroize(ctx context.Context, tenantID, keyID, requester, idempotencyKey string) (Result, error) {
	return s.destructive(ctx, tenantID, keyID, requester, idempotencyKey, ActionZeroize, byok.EventKeyZeroized,
		func(ctx context.Context, rec *record) error {
			if err := s.backend.ZeroizeKey(ctx, rec.ref); err != nil {
				return fmt.Errorf("managedkeys: zeroize: %w", err)
			}
			rec.state = byok.StateZeroized
			return nil
		})
}

// destructive runs a rotate/revoke/zeroize: it resolves the record, enforces dual
// control (fail-closed before the provider is touched), performs the provider op via
// apply, emits the AN-2 event, and returns the new metadata — all idempotent on the
// key. The provider op mutates rec in place; the event is emitted only after the
// provider succeeds, so a failed provider call records nothing.
func (s *Service) destructive(ctx context.Context, tenantID, keyID, requester, idempotencyKey, action, eventType string, apply func(context.Context, *record) error) (Result, error) {
	if tenantID == "" {
		return Result{}, ErrTenantRequired
	}
	if keyID == "" {
		return Result{}, ErrKeyRefRequired
	}
	return s.dedupe(ctx, tenantID, idempotencyKey, func(ctx context.Context) (Result, error) {
		// Dual control FIRST, before any provider side effect (fail-closed).
		if s.gate != nil {
			approved, reason := s.gate.IsApproved(ctx, tenantID, keyID, action, requester)
			if !approved {
				return Result{}, fmt.Errorf("%w: %s", ErrNotApproved, reason)
			}
		}
		s.mu.Lock()
		rec, ok := s.keys[mapKey(tenantID, keyID)]
		s.mu.Unlock()
		if !ok {
			return Result{}, ErrUnknownKey
		}
		priorVersion := rec.version
		priorID := rec.ref.ID
		if err := apply(ctx, rec); err != nil {
			return Result{}, err
		}
		// A rotate mints a successor whose provider id differs; re-index the record
		// under the new id (keeping the same logical record/version chain) so a
		// follow-on revoke/zeroize targets the current generation. The logical key id
		// the operator manages is the latest ref id.
		if rec.ref.ID != priorID {
			s.mu.Lock()
			delete(s.keys, mapKey(tenantID, priorID))
			s.keys[mapKey(tenantID, rec.ref.ID)] = rec
			s.mu.Unlock()
		}
		replaces := 0
		if eventType == byok.EventKeyRotated {
			replaces = priorVersion
		}
		if err := s.emit(ctx, eventType, tenantID, rec, byok.OriginGenerated, replaces); err != nil {
			return Result{}, err
		}
		return resultOf(rec), nil
	})
}

// dedupe routes a mutation through the idempotency recorder when one is configured
// and a key is supplied; otherwise it runs fn directly.
func (s *Service) dedupe(ctx context.Context, tenantID, key string, fn func(context.Context) (Result, error)) (Result, error) {
	if s.idem == nil || key == "" {
		return fn(ctx)
	}
	return s.idem.Do(ctx, tenantID, key, fn)
}

// emit publishes the AN-2 lifecycle event for rec. A dropped event makes the key
// history unrebuildable, so a sink error aborts the operation.
func (s *Service) emit(ctx context.Context, eventType, tenantID string, rec *record, origin byok.Origin, replaces int) error {
	ev := byok.LifecycleEvent{
		Type:      eventType,
		TenantID:  tenantID,
		KeyID:     rec.ref.ID,
		Version:   rec.version,
		Algorithm: string(rec.ref.Algorithm),
		Origin:    origin,
		Kind:      "signing",
		PublicDER: append([]byte(nil), rec.pub.DER...),
		Replaces:  replaces,
		Time:      s.clock().UTC(),
	}
	if err := s.sink.Emit(ctx, ev); err != nil {
		return fmt.Errorf("managedkeys: record %s event: %w", eventType, err)
	}
	return nil
}

func resultOf(rec *record) Result {
	return Result{
		KeyID:     rec.ref.ID,
		Algorithm: rec.ref.Algorithm,
		Version:   rec.version,
		State:     string(rec.state),
		PublicDER: append([]byte(nil), rec.pub.DER...),
	}
}

// Track registers an externally-minted key under the service's bookkeeping so a
// later rotate/revoke/zeroize can target it. The served control plane calls this on
// startup when rebuilding from the byok.key.generated event log, and the API uses it
// when an operator brings an existing provider key under management. It holds no
// private material.
func (s *Service) Track(tenantID string, ref crypto.KeyRef, version int, pub crypto.PublicKey, state byok.State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[mapKey(tenantID, ref.ID)] = &record{ref: ref, version: version, state: state, pub: pub}
}
