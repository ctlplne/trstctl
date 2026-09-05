// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	trstcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// Message is one external call to perform, as recorded in the outbox. The
// dispatcher hands it to a Handler; the IdempotencyKey lets the receiver collapse
// at-least-once redeliveries to a single effect (the AN-5 ↔ AN-6 bridge).
type Message struct {
	ID             int64
	TenantID       string
	Destination    string
	IdempotencyKey string
	Payload        []byte
	Attempts       int
	EffectLane     string
	// RequiredAgentRole is copied from the durable row into the delivery
	// attempt. Reservation cannot constrain a control-plane handler unless that
	// handler can see which executor owns the row.
	RequiredAgentRole string
}

// Entry is a new outbox row to enqueue alongside a state change.
type Entry struct {
	TenantID       string
	Destination    string
	IdempotencyKey string
	Payload        []byte
	// EffectLane partitions unrelated receivers that share one destination.
	// Empty defaults to Destination for backward-compatible strict ordering.
	EffectLane string
	// RequiredAgentRole is the agent role this row demands if an agent claims it
	// (epic A3): "" for kind-level rules only, "host"/"network" to demand that
	// role, "control_plane" to make the row never agent-claimable. Stamped at
	// enqueue from the target's vantage — the one moment the enqueuing code
	// knows what the target is — and read back as a plain column by the claim
	// SQL, which cannot decode a sealed payload.
	RequiredAgentRole string
	// RequiredAgentID narrows the row to ONE agent (epic A5). An agent.upgrade
	// job is an instruction to a specific machine to replace its own binary;
	// letting any fleet member claim it would hand agent A the order meant for
	// agent B. Empty means no per-agent demand.
	RequiredAgentID string
}

// OutboxCommandConflictError identifies both sides of a receiver-key collision
// without copying executable payloads into logs or error strings. Callers that
// are explicitly recovery-aware may turn it into durable quarantine evidence;
// ordinary mutation paths still see store.ErrIdempotencyConflict and fail closed.
type OutboxCommandConflictError struct {
	TenantID                   string
	IdempotencyKey             string
	ExistingOutboxID           int64
	ExistingDestination        string
	ExistingEffectLane         string
	ExistingPayloadSHA256      string
	ExistingRequiredAgentRole  string
	ExistingRequiredAgentID    string
	CandidateDestination       string
	CandidateEffectLane        string
	CandidatePayloadSHA256     string
	CandidateRequiredAgentRole string
	CandidateRequiredAgentID   string
}

func (e *OutboxCommandConflictError) Error() string {
	return store.ErrIdempotencyConflict.Error() + ": outbox key belongs to a different receiver command"
}

func (e *OutboxCommandConflictError) Unwrap() error { return store.ErrIdempotencyConflict }

// Record is the observable state of an outbox row, including its retry bookkeeping.
type Record struct {
	ID             int64
	TenantID       string
	Destination    string
	IdempotencyKey string
	Status         string
	Attempts       int
	LastError      string
	Payload        []byte
	// LeaseHeld reports that a dispatch worker currently holds this row's lease
	// (status 'processing' with an unexpired lease_until). An in-request drainer
	// that performs the external call itself must skip such a row: the leaseholder
	// is already performing that same effect and is the only party allowed to
	// complete the row (AN-6).
	LeaseHeld bool
}

type claimedOutboxEntry struct {
	id       int64
	msg      Message
	attempts int
}

// CircuitState is the worker-side circuit breaker state for one tenant/destination.
type CircuitState string

const (
	CircuitClosed   CircuitState = "closed"
	CircuitOpen     CircuitState = "open"
	CircuitHalfOpen CircuitState = "half-open"
)

// CircuitSnapshot is the operator-visible retry circuit state for one tenant and
// outbox destination. It is in-memory worker state; durable delivery truth remains
// in the outbox rows.
type CircuitSnapshot struct {
	TenantID    string
	Destination string
	State       CircuitState
	Failures    int
	OpenUntil   time.Time
	UpdatedAt   time.Time
	LastError   string
}

// CircuitTransition is emitted whenever a tenant/destination circuit changes state.
type CircuitTransition struct {
	TenantID    string
	Destination string
	From        CircuitState
	To          CircuitState
	Failures    int
	OpenUntil   time.Time
}

type circuitKey struct {
	tenantID    string
	destination string
}

func (k circuitKey) string() string { return k.tenantID + "\x1f" + k.destination }

type outboxCircuit struct {
	state     CircuitState
	failures  int
	openUntil time.Time
	updatedAt time.Time
	lastError string
}

// Handler performs the external call for a Message. It must be idempotent on the
// message's IdempotencyKey, since delivery is at-least-once.
type Handler interface {
	Deliver(ctx context.Context, m Message) error
}

// DestinationScope confines one dispatcher sweep to a disjoint destination
// family. IncludePrefixes selects matching destinations; ExcludePrefixes removes
// matches. Empty include/exclude slices mean all destinations, preserving the
// legacy Dispatch behavior. Prefixes are compared literally, never as SQL LIKE
// patterns.
type DestinationScope struct {
	IncludePrefixes []string
	ExcludePrefixes []string
}

func (s DestinationScope) validate() error {
	seen := make(map[string]string, len(s.IncludePrefixes)+len(s.ExcludePrefixes))
	for kind, prefixes := range map[string][]string{"include": s.IncludePrefixes, "exclude": s.ExcludePrefixes} {
		for _, prefix := range prefixes {
			if prefix == "" {
				return fmt.Errorf("orchestrator: outbox destination scope has an empty %s prefix", kind)
			}
			if prior, ok := seen[prefix]; ok {
				return fmt.Errorf("orchestrator: outbox destination prefix %q appears in both/duplicate %s and %s sets", prefix, prior, kind)
			}
			seen[prefix] = kind
		}
	}
	return nil
}

func (s DestinationScope) matches(destination string) bool {
	included := len(s.IncludePrefixes) == 0
	for _, prefix := range s.IncludePrefixes {
		if strings.HasPrefix(destination, prefix) {
			included = true
			break
		}
	}
	if !included {
		return false
	}
	for _, prefix := range s.ExcludePrefixes {
		if strings.HasPrefix(destination, prefix) {
			return false
		}
	}
	return true
}

// TerminalFailureHandler records a domain terminal-state fact before an outbox
// row is dead-lettered. The event/projection write happens while the row still has
// a recoverable processing lease; if it fails, Dispatch leaves the lease intact so
// recovery retries the failure fact instead of silently losing user-visible state.
type TerminalFailureHandler interface {
	DeliverTerminalFailure(ctx context.Context, m Message, cause error) error
}

// HandlerFunc adapts a function to a Handler.
type HandlerFunc func(ctx context.Context, m Message) error

// Deliver calls f.
func (f HandlerFunc) Deliver(ctx context.Context, m Message) error { return f(ctx, m) }

// DeliveryDeferredError means the worker could not start its receiver effect
// because a local operator-controlled prerequisite is temporarily closed. ELI5:
// this is a pause, not a failed attempt. The outbox keeps the row pending and
// refunds the claim attempt so a long tenant seal cannot consume the dead-letter
// budget before an operator unseals it.
type DeliveryDeferredError struct{ cause error }

func (e *DeliveryDeferredError) Error() string { return "outbox delivery deferred" }
func (e *DeliveryDeferredError) Unwrap() error { return e.cause }

// DeferDelivery marks err as a retry-budget-neutral delivery pause. Callers must
// use it only before receiver I/O begins; otherwise refunding the attempt could
// hide an ambiguous external side effect.
func DeferDelivery(err error) error {
	if err == nil || IsDeliveryDeferred(err) {
		return err
	}
	return &DeliveryDeferredError{cause: err}
}

// IsDeliveryDeferred reports whether a handler explicitly proved that receiver
// I/O did not begin and the claim may be retried without consuming an attempt.
func IsDeliveryDeferred(err error) bool {
	var deferred *DeliveryDeferredError
	return errors.As(err, &deferred)
}

// DefiniteNoEffectError proves that a failed delivery returned before receiver
// I/O began. Only this proof lets a domain terminal callback turn retry
// exhaustion into a permanent failed fact. A timeout, lost response, or ordinary
// transport error is deliberately NOT this type because the receiver may already
// have committed the operation.
type DefiniteNoEffectError struct{ cause error }

func (e *DefiniteNoEffectError) Error() string {
	if e.cause == nil {
		return "outbox delivery had no external effect"
	}
	return e.cause.Error()
}
func (e *DefiniteNoEffectError) Unwrap() error { return e.cause }

// DefiniteNoEffect marks a pre-I/O failure. Callers must not use it after opening
// a receiver request; doing so could let a newer ordered command overtake an old
// write whose response was merely lost.
func DefiniteNoEffect(err error) error {
	if err == nil || IsDefiniteNoEffect(err) {
		return err
	}
	return &DefiniteNoEffectError{cause: err}
}

// IsDefiniteNoEffect reports whether the delivery path supplied the typed proof.
func IsDefiniteNoEffect(err error) bool {
	var definite *DefiniteNoEffectError
	return errors.As(err, &definite)
}

// Outbox implements AN-6: external calls are recorded in the same transaction as
// the state change that triggers them (Enqueue), and a separate worker performs
// them (Dispatch). This gives at-least-once delivery; an idempotent Handler makes
// the net effect exactly-once. The internal/outboxgc retention sweep bounds the
// table by reclaiming delivered rows past a retention window (SPINE-003); it lives
// outside this repository package because it is a deliberate cross-tenant system
// operation, like the idempotency-key GC.
type Outbox struct {
	store                     *store.Store
	backoff                   func(attempts int) time.Duration
	jitter                    func(time.Duration) time.Duration
	now                       func() time.Time
	maxAttempts               int
	leaseTTL                  time.Duration
	deliveryTimeout           time.Duration
	deliveryTimeoutObserver   func(Message)
	maxInFlightPerDestination int
	maxInFlightPerTenant      int
	workerID                  string

	circuitMu               sync.Mutex
	circuits                map[circuitKey]*outboxCircuit
	circuitFailureThreshold int
	circuitOpenDuration     time.Duration
	circuitObserver         func(CircuitTransition)
}

// Option configures an Outbox.
type Option func(*Outbox)

// WithBackoff sets the delay before a failed entry becomes eligible for retry,
// as a function of the new attempt count.
func WithBackoff(f func(attempts int) time.Duration) Option {
	return func(o *Outbox) { o.backoff = f }
}

// WithRetryJitter sets the jitter applied to the base retry backoff. It is mainly
// useful for deterministic tests; production uses bounded random jitter.
func WithRetryJitter(f func(time.Duration) time.Duration) Option {
	return func(o *Outbox) {
		if f != nil {
			o.jitter = f
		}
	}
}

// WithNow injects the worker clock. It is used by deterministic retry/circuit
// tests; production uses time.Now.
func WithNow(f func() time.Time) Option {
	return func(o *Outbox) {
		if f != nil {
			o.now = f
		}
	}
}

// WithMaxAttempts sets how many attempts an entry gets before it is dead-lettered
// (marked failed and no longer dispatched).
func WithMaxAttempts(n int) Option {
	return func(o *Outbox) { o.maxAttempts = n }
}

// WithLeaseTTL sets how long a claimed row may remain processing before another
// worker can recover it. A non-positive value leaves the production default.
func WithLeaseTTL(n time.Duration) Option {
	return func(o *Outbox) {
		if n > 0 {
			o.leaseTTL = n
		}
	}
}

// WithDeliveryTimeout sets the per-message deadline for the external call made
// by Dispatch. A non-positive value leaves the production default.
func WithDeliveryTimeout(n time.Duration) Option {
	return func(o *Outbox) {
		if n > 0 {
			o.deliveryTimeout = n
		}
	}
}

// WithDeliveryTimeoutObserver records delivery deadline expirations without
// coupling the orchestrator package to a concrete metrics implementation.
func WithDeliveryTimeoutObserver(f func(Message)) Option {
	return func(o *Outbox) { o.deliveryTimeoutObserver = f }
}

// WithCircuitBreaker sets the consecutive-failure threshold and open duration for
// a tenant/destination circuit. A non-positive threshold disables the circuit.
func WithCircuitBreaker(failureThreshold int, openFor time.Duration) Option {
	return func(o *Outbox) {
		o.circuitFailureThreshold = failureThreshold
		if openFor > 0 {
			o.circuitOpenDuration = openFor
		}
	}
}

// WithCircuitObserver records circuit transitions without coupling this package to
// a concrete metrics implementation.
func WithCircuitObserver(f func(CircuitTransition)) Option {
	return func(o *Outbox) { o.circuitObserver = f }
}

// WithMaxInFlightPerDestination caps concurrently processing rows for one
// tenant/effective receiver lane. This prevents one down CA/connector/webhook
// from occupying every outbox worker without coupling a same-named receiver in
// another tenant to that tenant's capacity.
func WithMaxInFlightPerDestination(n int) Option {
	return func(o *Outbox) {
		if n > 0 {
			o.maxInFlightPerDestination = n
		}
	}
}

// WithMaxInFlightPerTenant caps concurrently processing rows for one tenant so a
// noisy tenant leaves outbox capacity for unrelated tenants.
func WithMaxInFlightPerTenant(n int) Option {
	return func(o *Outbox) {
		if n > 0 {
			o.maxInFlightPerTenant = n
		}
	}
}

// WithWorkerID sets the lease owner written to claimed rows. It is mainly useful
// for deterministic tests and diagnostics; production callers can use the default.
func WithWorkerID(id string) Option {
	return func(o *Outbox) {
		if id != "" {
			o.workerID = id
		}
	}
}

// NewOutbox returns an Outbox backed by the given store. By default it retries
// with capped exponential backoff plus jitter and dead-letters after 10 attempts.
func NewOutbox(s *store.Store, opts ...Option) *Outbox {
	o := &Outbox{
		store:                     s,
		backoff:                   defaultOutboxBackoff,
		jitter:                    defaultOutboxJitter,
		now:                       time.Now,
		maxAttempts:               10,
		leaseTTL:                  30 * time.Second,
		deliveryTimeout:           25 * time.Second,
		maxInFlightPerDestination: 1,
		maxInFlightPerTenant:      2,
		workerID:                  fmt.Sprintf("outbox-%d", time.Now().UTC().UnixNano()),
		circuits:                  make(map[circuitKey]*outboxCircuit),
		circuitFailureThreshold:   3,
		circuitOpenDuration:       30 * time.Second,
	}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

func defaultOutboxBackoff(attempts int) time.Duration {
	const capDelay = 5 * time.Minute
	if attempts <= 0 {
		return time.Second
	}
	delay := time.Second
	for i := 1; i < attempts; i++ {
		if delay >= capDelay/2 {
			return capDelay
		}
		delay *= 2
	}
	if delay > capDelay {
		return capDelay
	}
	return delay
}

func defaultOutboxJitter(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	floor := base / 2
	span := base - floor
	if span <= 0 {
		return base
	}
	return floor + time.Duration(rand.Int63n(int64(span)+1)) // #nosec G404 -- retry backoff jitter, not a security decision (CWE-338)
}

func (o *Outbox) clockNow() time.Time { return o.now().UTC() }

// Enqueue records an outbox entry on the caller's transaction, so the intent is
// durable iff the state change it accompanies commits (AN-6). It returns the new
// entry's id.
func (o *Outbox) Enqueue(ctx context.Context, tx pgx.Tx, e Entry) (int64, error) {
	lane := effectiveOutboxLane(e.Destination, e.EffectLane)
	var id int64
	err := tx.QueryRow(ctx,
		`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, effect_lane, required_agent_role, required_agent_id)
		 VALUES ($1, $2, $3, $4, $5, $6, nullif($7, '')::uuid)
		 RETURNING id`,
		e.TenantID, e.Destination, e.Payload, e.IdempotencyKey, lane, e.RequiredAgentRole, e.RequiredAgentID).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("orchestrator: enqueue outbox: %w", err)
	}
	return id, nil
}

// EnqueueIfAbsent records an outbox entry on the caller's transaction ONLY if no
// entry with the same (tenant_id, idempotency_key) already exists, and reports
// whether it inserted (SPINE-011). It is the idempotent enqueue the reconciliation
// pass uses to heal a side effect that an append-then-project crash never recorded:
// the inline Transition path enqueues with IdempotencyKey = the lifecycle event's
// globally-unique ID, so an event whose effect already landed is left untouched,
// and one whose effect was lost is enqueued exactly once. The conditional insert is
// atomic within the caller's transaction, so two concurrent reconcilers cannot both
// insert the same key. It runs under the tenant's RLS context, like Enqueue.
func (o *Outbox) EnqueueIfAbsent(ctx context.Context, tx pgx.Tx, e Entry) (inserted bool, err error) {
	lane := effectiveOutboxLane(e.Destination, e.EffectLane)
	// READ COMMITTED does not make INSERT ... WHERE NOT EXISTS safe when two
	// transactions start together: each snapshot can see "absent" and both can
	// insert. Serialize only this tenant/key pair for the lifetime of the caller's
	// transaction. The tenant is part of the lock identity, preserving AN-1 while
	// allowing the same receiver key in different tenants to proceed independently.
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"outbox-enqueue-if-absent\x1f"+e.TenantID+"\x1f"+e.IdempotencyKey); err != nil {
		return false, fmt.Errorf("orchestrator: lock enqueue-if-absent outbox: %w", err)
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, effect_lane, required_agent_role, required_agent_id)
		 SELECT $1, $2, $3, $4, $5, $6, nullif($7, '')::uuid
		 WHERE NOT EXISTS (
		     SELECT 1 FROM outbox WHERE tenant_id = $1 AND idempotency_key = $4
		 )`,
		e.TenantID, e.Destination, e.Payload, e.IdempotencyKey, lane, e.RequiredAgentRole, e.RequiredAgentID)
	if err != nil {
		return false, fmt.Errorf("orchestrator: enqueue-if-absent outbox: %w", err)
	}
	if tag.RowsAffected() > 0 {
		return true, nil
	}

	// A raw idempotency key identifies one exact receiver command, not merely one
	// row. Returning an unrelated row here makes a mutation look queued while a
	// different subsystem, destination, or payload will actually execute. Compare
	// the durable command before reporting a replay; callers may then safely use
	// the outbox itself as the post-response-cache idempotency authority.
	var destination, existingLane, existingRole, existingAgentID string
	var existingID int64
	var payload []byte
	if err := tx.QueryRow(ctx,
		`SELECT id, destination, payload, COALESCE(NULLIF(effect_lane, ''), destination),
		        COALESCE(required_agent_role, ''), COALESCE(required_agent_id::text, '')
		   FROM outbox
		  WHERE tenant_id = $1 AND idempotency_key = $2
		  ORDER BY id
		  LIMIT 1`,
		e.TenantID, e.IdempotencyKey).Scan(&existingID, &destination, &payload, &existingLane, &existingRole, &existingAgentID); err != nil {
		return false, fmt.Errorf("orchestrator: load enqueue-if-absent outbox replay: %w", err)
	}
	if destination != e.Destination || existingLane != lane || !bytes.Equal(payload, e.Payload) ||
		existingRole != e.RequiredAgentRole || existingAgentID != e.RequiredAgentID {
		return false, &OutboxCommandConflictError{
			TenantID: e.TenantID, IdempotencyKey: e.IdempotencyKey,
			ExistingOutboxID: existingID, ExistingDestination: destination,
			ExistingEffectLane: existingLane, ExistingPayloadSHA256: trstcrypto.SHA256Hex(payload),
			ExistingRequiredAgentRole: existingRole, ExistingRequiredAgentID: existingAgentID,
			CandidateDestination: e.Destination, CandidateEffectLane: lane,
			CandidatePayloadSHA256:     trstcrypto.SHA256Hex(e.Payload),
			CandidateRequiredAgentRole: e.RequiredAgentRole, CandidateRequiredAgentID: e.RequiredAgentID,
		}
	}
	return false, nil
}

// rewriteCanonicalIfPresent replaces only the executable payload of the exact
// tenant/idempotency-key command after a privacy history rewrite. Delivery state,
// attempts, receipts, and scheduling stay untouched. The same advisory lock as
// EnqueueIfAbsent closes the missing-row/reconciliation race.
//
// A processing row is never rewritten: a worker may already hold its old bytes
// outside PostgreSQL. The erasure must retry after that claim finishes so success
// never means raw personal data is still executing in another address space.
func (o *Outbox) rewriteCanonicalIfPresent(ctx context.Context, tx pgx.Tx, e Entry) (bool, error) {
	lane := effectiveOutboxLane(e.Destination, e.EffectLane)
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"outbox-enqueue-if-absent\x1f"+e.TenantID+"\x1f"+e.IdempotencyKey); err != nil {
		return false, fmt.Errorf("orchestrator: lock canonical outbox rewrite: %w", err)
	}

	var (
		existingID, duplicateCount                       int64
		destination, existingLane, existingRole, agentID string
		status                                           string
		payload                                          []byte
	)
	err := tx.QueryRow(ctx,
		`SELECT o.id, o.destination, o.payload,
		        COALESCE(NULLIF(o.effect_lane, ''), o.destination),
		        COALESCE(o.required_agent_role, ''),
		        COALESCE(o.required_agent_id::text, ''), o.status,
		        (SELECT count(*) FROM outbox duplicates
		          WHERE duplicates.tenant_id = $1 AND duplicates.idempotency_key = $2)
		   FROM outbox o
		  WHERE o.tenant_id = $1 AND o.idempotency_key = $2
		  ORDER BY o.id
		  LIMIT 1
		  FOR UPDATE OF o`, e.TenantID, e.IdempotencyKey).Scan(
		&existingID, &destination, &payload, &existingLane, &existingRole,
		&agentID, &status, &duplicateCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("orchestrator: load canonical outbox rewrite target: %w", err)
	}
	if duplicateCount != 1 {
		return false, fmt.Errorf("%w: canonical outbox rewrite found duplicate receiver keys", store.ErrIdempotencyConflict)
	}
	if destination != e.Destination || existingLane != lane || existingRole != e.RequiredAgentRole || agentID != e.RequiredAgentID {
		return false, &OutboxCommandConflictError{
			TenantID: e.TenantID, IdempotencyKey: e.IdempotencyKey,
			ExistingOutboxID: existingID, ExistingDestination: destination,
			ExistingEffectLane: existingLane, ExistingPayloadSHA256: trstcrypto.SHA256Hex(payload),
			ExistingRequiredAgentRole: existingRole, ExistingRequiredAgentID: agentID,
			CandidateDestination: e.Destination, CandidateEffectLane: lane,
			CandidatePayloadSHA256:     trstcrypto.SHA256Hex(e.Payload),
			CandidateRequiredAgentRole: e.RequiredAgentRole, CandidateRequiredAgentID: e.RequiredAgentID,
		}
	}
	if status == "processing" {
		return false, ErrOutboxLeaseHeld
	}
	if bytes.Equal(payload, e.Payload) {
		return true, nil
	}
	command, err := tx.Exec(ctx,
		`UPDATE outbox SET payload = $3 WHERE tenant_id = $1 AND id = $2`,
		e.TenantID, existingID, e.Payload)
	if err != nil {
		return false, fmt.Errorf("orchestrator: rewrite canonical outbox payload: %w", err)
	}
	if command.RowsAffected() != 1 {
		return false, fmt.Errorf("orchestrator: canonical outbox rewrite target disappeared")
	}
	return true, nil
}

func effectiveOutboxLane(destination, lane string) string {
	lane = strings.TrimSpace(lane)
	if lane == "" {
		return destination
	}
	return lane
}

func tenantEffectiveOutboxLaneKey(tenantID, destination, lane string) string {
	return circuitKey{
		tenantID:    tenantID,
		destination: effectiveOutboxLane(destination, lane),
	}.string()
}

// Dispatch performs entries that are due now, one leased row at a time, and
// returns how many it attempted. A Handler failure is not a Dispatch error: it is
// recorded on the row (attempts, last_error, next_attempt_at) for a later retry,
// or dead-lettered once the attempt cap is reached. Only a database/transport
// fault aborts Dispatch.
//
// Entries scheduled into the future (a failed entry serving its backoff) and
// entries already handled in this run are skipped, so one Dispatch call drains the
// currently-due backlog without spinning on a zero-backoff failure. Fairness is
// round-robin by tenant and effective receiver lane: each round claims at most
// one row per tenant and one row per tenant/lane, then starts a new round if more
// due work remains.
func (o *Outbox) Dispatch(ctx context.Context, h Handler) (int, error) {
	return o.DispatchScoped(ctx, h, DestinationScope{})
}

// DispatchScoped is Dispatch constrained to one destination family. Separate
// family pools call it concurrently; every claim, expired-lease recovery,
// per-tenant in-flight count, and half-open circuit reservation is scoped to the
// same family, so a saturated connector lane cannot suppress another lane.
func (o *Outbox) DispatchScoped(ctx context.Context, h Handler, scope DestinationScope) (int, error) {
	if err := scope.validate(); err != nil {
		return 0, err
	}
	cutoff := o.clockNow()
	seenTenants := make(map[string]bool)
	seenTenantLanes := make(map[string]bool)
	processed := 0
	for {
		claim, claimed, err := o.claimOne(ctx, cutoff, seenTenants, seenTenantLanes, scope)
		if err != nil {
			return processed, err
		}
		if !claimed {
			if len(seenTenants) == 0 && len(seenTenantLanes) == 0 {
				break
			}
			seenTenants = make(map[string]bool)
			seenTenantLanes = make(map[string]bool)
			continue
		}

		seenTenants[claim.msg.TenantID] = true
		seenTenantLanes[tenantEffectiveOutboxLaneKey(claim.msg.TenantID, claim.msg.Destination, claim.msg.EffectLane)] = true
		processed++
		if err := o.dispatchClaim(ctx, h, claim); err != nil {
			return processed, err
		}
	}
	return processed, nil
}

// DispatchOneScoped attempts at most one currently due row from one destination
// family. It is the exact primitive for a caller already holding one durable
// command receipt: unlike DispatchScoped, it does not perform a second empty-queue
// sweep merely to prove that unrelated work is absent.
func (o *Outbox) DispatchOneScoped(ctx context.Context, h Handler, scope DestinationScope) (bool, error) {
	if err := scope.validate(); err != nil {
		return false, err
	}
	claim, claimed, err := o.claimOne(ctx, o.clockNow(), map[string]bool{}, map[string]bool{}, scope)
	if err != nil || !claimed {
		return claimed, err
	}
	return true, o.dispatchClaim(ctx, h, claim)
}

func (o *Outbox) dispatchClaim(ctx context.Context, h Handler, claim claimedOutboxEntry) error {
	deliverErr := o.deliver(ctx, h, claim)
	if deliverErr != nil && !IsDeliveryDeferred(deliverErr) && claim.attempts >= o.maxAttempts {
		if terminal, ok := h.(TerminalFailureHandler); ok {
			if err := terminal.DeliverTerminalFailure(ctx, claim.msg, deliverErr); IsDeliveryDeferred(err) {
				// The domain knows this failure is ambiguous. Keep the durable
				// command pending, refund this claim, and preserve its FIFO barrier
				// until reconciliation or a later idempotent retry proves an outcome.
				deliverErr = err
			} else if err != nil {
				destroyDeliveryError(deliverErr)
				return fmt.Errorf("orchestrator: record terminal delivery failure: %w", err)
			}
		}
	}
	finalizeErr := o.finalizeClaim(ctx, claim, deliverErr)
	destroyDeliveryError(deliverErr)
	return finalizeErr
}

func (o *Outbox) deliver(ctx context.Context, h Handler, claim claimedOutboxEntry) error {
	deliverCtx := ctx
	cancel := func() {}
	if o.deliveryTimeout > 0 {
		deliverCtx, cancel = context.WithTimeout(ctx, o.deliveryTimeout)
	}
	deliverErr := h.Deliver(deliverCtx, claim.msg)
	timedOut := o.deliveryTimeout > 0 &&
		ctx.Err() == nil &&
		errors.Is(deliverCtx.Err(), context.DeadlineExceeded) &&
		errors.Is(deliverErr, context.DeadlineExceeded)
	cancel()
	if timedOut {
		if o.deliveryTimeoutObserver != nil {
			o.deliveryTimeoutObserver(claim.msg)
		}
		return fmt.Errorf("outbox delivery timed out after %s: %w", o.deliveryTimeout, deliverErr)
	}
	return deliverErr
}

// claimOne recovers expired leases, then marks one fair due row processing in a
// short transaction. The external call happens after this transaction commits, so
// slow destinations do not hold row locks, database transactions, or pool
// connections while the network is blocked.
func (o *Outbox) claimOne(ctx context.Context, cutoff time.Time, seenTenants, seenTenantLanes map[string]bool, scope DestinationScope) (claimedOutboxEntry, bool, error) {
	tx, err := o.store.SystemPool().Begin(ctx)
	if err != nil {
		return claimedOutboxEntry{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	now := o.clockNow()
	blockedCircuitKeys, reservedHalfOpen := o.reserveHalfOpenProbes(now, scope)
	if _, err := tx.Exec(ctx,
		//trstctl:system-query — lease recovery is a cross-tenant system worker path; expired processing rows are returned to their family's pending queue.
		`UPDATE outbox o
		    SET status = 'pending', worker_id = NULL, lease_until = NULL
		  WHERE o.status = 'processing' AND o.lease_until <= $1
		    AND (
		        COALESCE(cardinality($2::text[]), 0) = 0
		        OR EXISTS (
		            SELECT 1 FROM unnest($2::text[]) AS included(prefix)
		             WHERE left(o.destination, char_length(included.prefix)) = included.prefix
		        )
		    )
		    AND NOT EXISTS (
		        SELECT 1 FROM unnest($3::text[]) AS excluded(prefix)
		         WHERE left(o.destination, char_length(excluded.prefix)) = excluded.prefix
		    )`, now, scope.IncludePrefixes, scope.ExcludePrefixes); err != nil {
		o.releaseUnclaimedHalfOpenProbes(reservedHalfOpen, circuitKey{}, now)
		return claimedOutboxEntry{}, false, fmt.Errorf("orchestrator: recover expired outbox leases: %w", err)
	}

	leaseUntil := now.Add(o.leaseTTL)
	var claim claimedOutboxEntry
	err = tx.QueryRow(ctx,
		//trstctl:system-query — the dispatcher fairly drains every tenant's due entries; tenant_id is read back and carried in the Message. Cross-tenant by design (AN-1 exemption).
		`WITH candidate AS (
		     SELECT o.id
		       FROM outbox o
		      WHERE o.status = 'pending'
		        AND o.next_attempt_at <= $1
		        -- A row demanding one specific agent (A5: agent.upgrade) can
		        -- never be delivered by the control plane; only ClaimAgentJobs
		        -- may hand it out. Without this predicate the dispatcher would
		        -- sweep it on every tick into a handler that does not exist —
		        -- the exact stamped-but-unenforced defect E1 documented for
		        -- required_agent_role.
		        AND o.required_agent_id IS NULL
		        AND o.tenant_id::text <> ALL($7::text[])
		        AND (o.tenant_id::text || chr(31) || COALESCE(NULLIF(o.effect_lane, ''), o.destination)) <> ALL($8::text[])
		        AND (o.tenant_id::text || chr(31) || COALESCE(NULLIF(o.effect_lane, ''), o.destination)) <> ALL($9::text[])
		        AND (
		            COALESCE(cardinality($10::text[]), 0) = 0
		            OR EXISTS (
		                SELECT 1 FROM unnest($10::text[]) AS included(prefix)
		                 WHERE left(o.destination, char_length(included.prefix)) = included.prefix
		            )
		        )
		        AND NOT EXISTS (
		            SELECT 1 FROM unnest($11::text[]) AS excluded(prefix)
		             WHERE left(o.destination, char_length(excluded.prefix)) = excluded.prefix
		        )
		        -- Secret-sync ordering is a separate tenant+target causal fence.
		        -- effect_lane stays target-scoped for bulkheads/circuits; target_order
		        -- prevents a retry in backoff from being overtaken. Migration 0153's
		        -- trigger repeats this check for mixed-version workers whose SQL lacks it.
		        AND (
		            left(o.destination, 12) <> 'secret.sync.'
		            OR EXISTS (
		                SELECT 1
		                  FROM secret_sync_jobs current_sync
			                 WHERE current_sync.tenant_id = o.tenant_id
			                   AND current_sync.outbox_id = o.id
			                   AND current_sync.target_order = o.secret_sync_target_order
			                   AND (
			                       -- Terminal evidence with a pending outbox is the safe
			                       -- append/project-before-finalize crash shape. Its
			                       -- handler performs zero receiver I/O, so cleanup does
			                       -- not wait behind an ambiguous predecessor.
			                       current_sync.status IN ('delivered', 'failed')
			                       OR (
			                           current_sync.status = 'pending'
			                           AND (
			                               o.secret_sync_order_from_event = false
			                               OR EXISTS (
			                                   SELECT 1
			                                     FROM projection_checkpoint checkpoint
			                                    WHERE checkpoint.id = 1
			                                      AND checkpoint.applied_seq >= current_sync.target_order
			                               )
			                           )
				                           AND NOT EXISTS (
				                               SELECT 1
				                                 FROM outbox older_sync_outbox
				                                 LEFT JOIN secret_sync_jobs older_sync_job
				                                   ON older_sync_job.tenant_id = older_sync_outbox.tenant_id
				                                  AND older_sync_job.outbox_id = older_sync_outbox.id
				                                  AND older_sync_job.target_order = older_sync_outbox.secret_sync_target_order
				                                  AND older_sync_outbox.destination = 'secret.sync.' || older_sync_job.target
				                                WHERE older_sync_outbox.tenant_id = o.tenant_id
				                                  AND older_sync_outbox.destination = o.destination
				                                  AND older_sync_outbox.secret_sync_target_order < o.secret_sync_target_order
				                                  -- A missing/malformed job or a command with more
				                                  -- than one receiver-I/O start stays a barrier even
				                                  -- after SQL terminalization. Only one exact,
				                                  -- canonical terminal choice releases successors.
				                                  AND NOT COALESCE(
				                                      (older_sync_job.status = 'delivered'
				                                          AND older_sync_outbox.secret_sync_receiver_effect_state = 'effect_possible'
				                                          AND older_sync_outbox.secret_sync_receiver_io_starts = 1)
				                                      OR
				                                      (older_sync_job.status = 'failed'
				                                          AND older_sync_outbox.secret_sync_receiver_effect_state = 'failure_authorized'
				                                          AND older_sync_outbox.secret_sync_receiver_io_starts BETWEEN 0 AND 1
				                                          AND older_sync_outbox.secret_sync_failure_detail = older_sync_job.last_error
				                                          AND older_sync_outbox.secret_sync_failure_attempts = older_sync_job.attempts),
				                                      false
				                                  )
				                           )
			                       )
				                   )
		            )
		        )
		        AND (
		            SELECT count(*)
		              FROM outbox p
		             WHERE p.status = 'processing'
		               AND p.tenant_id = o.tenant_id
		               AND COALESCE(NULLIF(p.effect_lane, ''), p.destination) = COALESCE(NULLIF(o.effect_lane, ''), o.destination)
		               AND p.lease_until > $2
		        ) < $3
		        AND (
		            SELECT count(*)
		              FROM outbox p
		             WHERE p.status = 'processing'
		               AND p.tenant_id = o.tenant_id
		               AND p.lease_until > $2
		               AND (
		                   COALESCE(cardinality($10::text[]), 0) = 0
		                   OR EXISTS (
		                       SELECT 1 FROM unnest($10::text[]) AS included(prefix)
		                        WHERE left(p.destination, char_length(included.prefix)) = included.prefix
		                   )
		               )
		               AND NOT EXISTS (
		                   SELECT 1 FROM unnest($11::text[]) AS excluded(prefix)
		                    WHERE left(p.destination, char_length(excluded.prefix)) = excluded.prefix
		               )
		        ) < $4
		        AND (
		            -- Secret sync has an immutable event-sequence fence above. Its
		            -- SQL ids can be reversed when two projections commit out of
		            -- order, so applying the generic id-based lane fence as well
		            -- can make each row wait for the other forever.
		            left(o.destination, 12) = 'secret.sync.'
		            OR NOT EXISTS (
		                SELECT 1
		                  FROM outbox older
		                 WHERE older.status = 'pending'
		                   AND older.next_attempt_at <= $1
		                   AND older.tenant_id = o.tenant_id
		                   AND COALESCE(NULLIF(older.effect_lane, ''), older.destination) = COALESCE(NULLIF(o.effect_lane, ''), o.destination)
		                   AND (older.next_attempt_at, older.id) < (o.next_attempt_at, o.id)
		            )
		        )
		      ORDER BY o.next_attempt_at, o.id
		      FOR UPDATE OF o SKIP LOCKED
		      LIMIT 1
		)
		UPDATE outbox o
		   SET status = 'processing',
		       attempts = o.attempts + 1,
		       worker_id = $5,
		       lease_until = $6,
		       last_error = NULL
		  FROM candidate
		 WHERE o.id = candidate.id
		 RETURNING o.id, o.tenant_id::text, o.destination, o.payload, o.idempotency_key, o.attempts,
		           COALESCE(NULLIF(o.effect_lane, ''), o.destination),
		           COALESCE(o.required_agent_role, '')`,
		cutoff, now, o.maxInFlightPerDestination, o.maxInFlightPerTenant,
		o.workerID, leaseUntil, mapKeys(seenTenants), mapKeys(seenTenantLanes), blockedCircuitKeys,
		scope.IncludePrefixes, scope.ExcludePrefixes).
		Scan(&claim.id, &claim.msg.TenantID, &claim.msg.Destination, &claim.msg.Payload, &claim.msg.IdempotencyKey, &claim.attempts, &claim.msg.EffectLane, &claim.msg.RequiredAgentRole)
	if errors.Is(err, pgx.ErrNoRows) {
		o.releaseUnclaimedHalfOpenProbes(reservedHalfOpen, circuitKey{}, now)
		return claimedOutboxEntry{}, false, tx.Commit(ctx)
	}
	if err != nil {
		o.releaseUnclaimedHalfOpenProbes(reservedHalfOpen, circuitKey{}, now)
		return claimedOutboxEntry{}, false, fmt.Errorf("orchestrator: claim outbox: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		o.releaseUnclaimedHalfOpenProbes(reservedHalfOpen, circuitKey{}, now)
		return claimedOutboxEntry{}, false, err
	}
	claim.msg.ID = claim.id
	claim.msg.Attempts = claim.attempts
	o.releaseUnclaimedHalfOpenProbes(reservedHalfOpen, circuitKey{tenantID: claim.msg.TenantID, destination: effectiveOutboxLane(claim.msg.Destination, claim.msg.EffectLane)}, now)
	return claim, true, nil
}

func mapKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// finalizeClaim records the result in a second short transaction. If the worker
// dies after delivery but before this update, the lease expires and another worker
// redelivers with the same idempotency key.
func (o *Outbox) finalizeClaim(ctx context.Context, claim claimedOutboxEntry, deliverErr error) error {
	tx, err := o.store.SystemPool().Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if deliverErr != nil {
		deferred := IsDeliveryDeferred(deliverErr)
		status := "pending"
		if !deferred && claim.attempts >= o.maxAttempts {
			status = "failed"
		}
		now := o.clockNow()
		next := now.Add(o.retryDelay(claim.attempts))
		tag, err := tx.Exec(ctx,
			`UPDATE outbox
			    SET attempts = CASE WHEN $7 THEN GREATEST(attempts - 1, 0) ELSE attempts END,
			        last_error = CASE
			          WHEN last_error LIKE 'external_ca_%'
			           AND last_error <> 'external_ca_idempotency_failed'
			           AND $4 = 'external_ca_idempotency_failed'
			          THEN last_error
			          ELSE $4
			        END,
			        next_attempt_at = $5,
			        status = $6,
			        worker_id = NULL,
			        lease_until = NULL
			  WHERE id = $1
			    AND tenant_id = $2
			    AND status = 'processing'
			    AND worker_id = $3`,
			claim.id, claim.msg.TenantID, o.workerID, persistedDeliveryError(deliverErr), next, status, deferred)
		if err != nil {
			return fmt.Errorf("orchestrator: record failure: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("orchestrator: finalize outbox failure: lease for row %d was lost", claim.id)
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		if !deferred {
			o.recordCircuitFailure(claim.msg, deliverErr, now)
		}
		return nil
	}

	tag, err := tx.Exec(ctx,
		`UPDATE outbox
		    SET status = 'delivered',
		        delivered_at = now(),
		        last_error = NULL,
		        worker_id = NULL,
		        lease_until = NULL
		  WHERE id = $1
		    AND tenant_id = $2
		    AND status = 'processing'
		    AND worker_id = $3`,
		claim.id, claim.msg.TenantID, o.workerID)
	if err != nil {
		return fmt.Errorf("orchestrator: record delivery: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("orchestrator: finalize outbox delivery: lease for row %d was lost", claim.id)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	o.recordCircuitSuccess(claim.msg, o.clockNow())
	return nil
}

// ErrOutboxLeaseHeld reports that a completion was refused because a dispatch
// worker currently holds the row's lease. The leaseholder owns finalization, so
// the durable intent is not lost — but the caller must not report success, or it
// would retire an item whose effect another worker is still performing.
var ErrOutboxLeaseHeld = errors.New("orchestrator: outbox entry is leased by a dispatch worker")

// CompleteAgentJobClaim retires an agent-held external effect in the same
// PostgreSQL commit that closes its exact claim generation. Splitting those
// writes creates an impossible row: pending (so it can be executed again) but
// claim-completed (so no later attempt can ever finish it).
//
// The structured result is projected before this call. If this transaction is
// refused or interrupted, the claim remains open and the agent may retry; the
// result projector must therefore derive stable identities from the job's
// idempotency key.
func (o *Outbox) CompleteAgentJobClaim(ctx context.Context, tenantID, agentID string,
	jobID int64, attempt int, at time.Time) (completed bool, err error) {
	if tenantID == "" || agentID == "" || jobID <= 0 || attempt <= 0 {
		return false, errors.New("orchestrator: complete agent job requires tenant, agent, job and attempt")
	}
	msg := Message{ID: jobID, TenantID: tenantID}
	err = o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		scanErr := tx.QueryRow(ctx,
			`UPDATE outbox
			    SET claim_completed_at = $5,
			        status = 'delivered',
			        delivered_at = $5,
			        last_error = NULL,
			        worker_id = NULL,
			        lease_until = NULL
			  WHERE tenant_id = $1
			    AND id = $3
			    AND claimed_by_agent_id = $2::uuid
			    AND claim_attempts = $4
			    AND claim_expires_at >= $5
			    AND claim_completed_at IS NULL
			    AND status = 'pending'
			    AND delivered_at IS NULL
			RETURNING destination, idempotency_key,
			          COALESCE(NULLIF(effect_lane, ''), destination)`,
			tenantID, agentID, jobID, attempt, at.UTC()).
			Scan(&msg.Destination, &msg.IdempotencyKey, &msg.EffectLane)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		completed = true
		return nil
	})
	if err != nil || !completed {
		return completed, err
	}
	o.recordCircuitSuccess(msg, at.UTC())
	return true, nil
}

// CompleteByKey marks the tenant's (destination, idempotencyKey) entry delivered on
// behalf of an in-request drainer that performed the external call itself instead of
// going through DispatchScoped. It is the general non-claim completion outside
// finalizeClaim; CompleteAgentJobClaim is the narrower signed agent-result path.
// CompleteByKey carries the same two invariants:
//
//   - The lease predicate. finalizeClaim completes only a row this worker leased
//     ("status = 'processing' AND worker_id = $3"), which is what stops two workers
//     from completing the same item. A caller that never claimed the row holds no
//     lease, so the equivalent guarantee here is the inverse: refuse any row a
//     dispatch worker is currently holding and report ErrOutboxLeaseHeld. An expired
//     lease is fair game — claimOne's own recovery sweep already treats
//     "lease_until <= now" as reclaimable.
//   - The circuit breaker. finalizeClaim's success branch calls recordCircuitSuccess
//     so a destination that just answered stops being treated as failing. A
//     completion that skips it leaves the lane's circuit open and keeps the
//     dispatcher backing off a healthy endpoint.
//
// completed reports whether this call flipped the row; false with a nil error means
// the entry was already delivered or is no longer present. ErrOutboxLeaseHeld is
// never mapped to success: a caller that swallows it reports an item retired while
// the leaseholder is still performing its effect.
func (o *Outbox) CompleteByKey(ctx context.Context, tenantID, destination, idempotencyKey string) (completed bool, err error) {
	if tenantID == "" || destination == "" || idempotencyKey == "" {
		return false, errors.New("orchestrator: complete outbox entry requires tenant, destination and idempotency key")
	}
	now := o.clockNow()
	msg := Message{TenantID: tenantID, Destination: destination, IdempotencyKey: idempotencyKey}
	leaseHeld := false
	err = o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		scanErr := tx.QueryRow(ctx,
			`UPDATE outbox
			    SET status = 'delivered',
			        delivered_at = now(),
			        last_error = NULL,
			        worker_id = NULL,
			        lease_until = NULL
			  WHERE tenant_id = $1
			    AND destination = $2
			    AND idempotency_key = $3
			    AND status <> 'delivered'
			    AND (status <> 'processing' OR lease_until IS NULL OR lease_until <= $4)
			RETURNING id, COALESCE(NULLIF(effect_lane, ''), destination)`,
			tenantID, destination, idempotencyKey, now).
			Scan(&msg.ID, &msg.EffectLane)
		if !errors.Is(scanErr, pgx.ErrNoRows) {
			return scanErr
		}
		// Nothing flipped: either the entry is already delivered/absent, or a dispatch
		// worker holds a live lease on it. Tell those apart so a lease collision is
		// reported instead of silently reading like a replay.
		return tx.QueryRow(ctx,
			`SELECT count(*) > 0
			   FROM outbox
			  WHERE tenant_id = $1
			    AND destination = $2
			    AND idempotency_key = $3
			    AND status = 'processing'
			    AND lease_until > $4`,
			tenantID, destination, idempotencyKey, now).Scan(&leaseHeld)
	})
	if err != nil {
		return false, err
	}
	if leaseHeld {
		return false, ErrOutboxLeaseHeld
	}
	if msg.ID == 0 {
		return false, nil
	}
	o.recordCircuitSuccess(msg, now)
	return true, nil
}

// persistedDeliveryError is deliberately closed-set. An external system may echo
// the credential/private key just sent to it in an error response; persisting
// arbitrary err.Error() would turn that attacker-controlled body into an
// unwipeable Go string and durable PostgreSQL secret leak (AN-8).
func safePersistableDeliveryClass(err error) (string, bool) {
	// A subsystem may attach one of these closed, credential-free classes while
	// retaining its raw cause only in short-lived memory. Accept only this local
	// allowlist: an untrusted connector can implement the same method, but it
	// cannot choose arbitrary text that would become a durable secret leak.
	var classified interface{ SafeDeliveryClass() string }
	if errors.As(err, &classified) {
		switch class := classified.SafeDeliveryClass(); class {
		case "external_ca_account_failed", "external_ca_order_failed", "external_ca_finalize_failed", "external_ca_protocol_failed",
			"external_ca_provider_failed", "external_ca_record_failed", "external_ca_result_encode_failed",
			"external_ca_idempotency_failed", "external_ca_result_decode_failed", "external_ca_observation_failed":
			return class, true
		}
	}
	return "", false
}

func persistedDeliveryError(err error) string {
	if class, ok := safePersistableDeliveryClass(err); ok {
		return class
	}
	switch {
	case IsDeliveryDeferred(err):
		return "delivery_deferred"
	case errors.Is(err, context.DeadlineExceeded):
		return "external_delivery_timeout"
	case errors.Is(err, context.Canceled):
		return "external_delivery_canceled"
	default:
		return "external_delivery_failed"
	}
}

func destroyDeliveryError(err error) {
	if err == nil {
		return
	}
	var destroyer interface{ Destroy() }
	if errors.As(err, &destroyer) {
		destroyer.Destroy()
	}
}

func (o *Outbox) retryDelay(attempts int) time.Duration {
	base := o.backoff(attempts)
	if base <= 0 {
		return 0
	}
	delay := o.jitter(base)
	if delay < 0 {
		return 0
	}
	if delay > base {
		return base
	}
	return delay
}

func (o *Outbox) reserveHalfOpenProbes(now time.Time, scope DestinationScope) ([]string, map[circuitKey]bool) {
	if o.circuitFailureThreshold <= 0 {
		return []string{}, nil
	}
	var transitions []CircuitTransition

	o.circuitMu.Lock()
	o.pruneIdleCircuitsLocked(now)
	blocked := make([]string, 0, len(o.circuits))
	reserved := make(map[circuitKey]bool)
	for key, circuit := range o.circuits {
		if !scope.matches(key.destination) {
			continue
		}
		switch circuit.state {
		case CircuitOpen:
			if now.Before(circuit.openUntil) {
				blocked = append(blocked, key.string())
				continue
			}
			from := circuit.state
			circuit.state = CircuitHalfOpen
			circuit.updatedAt = now
			reserved[key] = true
			transitions = append(transitions, CircuitTransition{
				TenantID: key.tenantID, Destination: key.destination,
				From: from, To: circuit.state, Failures: circuit.failures, OpenUntil: circuit.openUntil,
			})
		case CircuitHalfOpen:
			blocked = append(blocked, key.string())
		}
	}
	o.circuitMu.Unlock()

	o.emitCircuitTransitions(transitions)
	return blocked, reserved
}

func (o *Outbox) releaseUnclaimedHalfOpenProbes(reserved map[circuitKey]bool, claimed circuitKey, now time.Time) {
	if len(reserved) == 0 {
		return
	}
	o.circuitMu.Lock()
	for key := range reserved {
		if key == claimed {
			continue
		}
		if circuit := o.circuits[key]; circuit != nil && circuit.state == CircuitHalfOpen {
			circuit.state = CircuitOpen
			circuit.openUntil = now
			circuit.updatedAt = now
		}
	}
	o.circuitMu.Unlock()
}

func (o *Outbox) recordCircuitFailure(m Message, err error, now time.Time) {
	if o.circuitFailureThreshold <= 0 {
		return
	}
	key := circuitKey{tenantID: m.TenantID, destination: effectiveOutboxLane(m.Destination, m.EffectLane)}
	var transition *CircuitTransition

	o.circuitMu.Lock()
	circuit := o.circuits[key]
	if circuit == nil {
		circuit = &outboxCircuit{state: CircuitClosed}
		o.circuits[key] = circuit
	}
	from := circuit.state
	circuit.failures++
	circuit.lastError = persistedDeliveryError(err)
	circuit.updatedAt = now
	if circuit.state == CircuitHalfOpen || circuit.failures >= o.circuitFailureThreshold {
		circuit.state = CircuitOpen
		circuit.openUntil = now.Add(o.circuitOpenDuration)
	}
	if from != circuit.state {
		transition = &CircuitTransition{
			TenantID: key.tenantID, Destination: key.destination,
			From: from, To: circuit.state, Failures: circuit.failures, OpenUntil: circuit.openUntil,
		}
	}
	o.circuitMu.Unlock()

	if transition != nil {
		o.emitCircuitTransitions([]CircuitTransition{*transition})
	}
}

func (o *Outbox) recordCircuitSuccess(m Message, now time.Time) {
	if o.circuitFailureThreshold <= 0 {
		return
	}
	key := circuitKey{tenantID: m.TenantID, destination: effectiveOutboxLane(m.Destination, m.EffectLane)}
	var transition *CircuitTransition

	o.circuitMu.Lock()
	circuit := o.circuits[key]
	if circuit != nil {
		from := circuit.state
		circuit.state = CircuitClosed
		circuit.failures = 0
		circuit.openUntil = time.Time{}
		circuit.updatedAt = now
		circuit.lastError = ""
		if from != circuit.state {
			transition = &CircuitTransition{
				TenantID: key.tenantID, Destination: key.destination,
				From: from, To: circuit.state, Failures: circuit.failures,
			}
		}
	}
	o.circuitMu.Unlock()

	if transition != nil {
		o.emitCircuitTransitions([]CircuitTransition{*transition})
	}
}

func (o *Outbox) emitCircuitTransitions(transitions []CircuitTransition) {
	if o.circuitObserver == nil {
		return
	}
	for _, tr := range transitions {
		o.circuitObserver(tr)
	}
}

// CircuitStates returns a deterministic snapshot of the worker's per-tenant,
// per-destination circuit states for operator-facing status surfaces.
func (o *Outbox) CircuitStates() []CircuitSnapshot {
	o.circuitMu.Lock()
	defer o.circuitMu.Unlock()
	out := make([]CircuitSnapshot, 0, len(o.circuits))
	for key, circuit := range o.circuits {
		out = append(out, CircuitSnapshot{
			TenantID: key.tenantID, Destination: key.destination,
			State: circuit.state, Failures: circuit.failures, OpenUntil: circuit.openUntil,
			UpdatedAt: circuit.updatedAt, LastError: circuit.lastError,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TenantID != out[j].TenantID {
			return out[i].TenantID < out[j].TenantID
		}
		return out[i].Destination < out[j].Destination
	})
	return out
}

// Pending returns the tenant's not-yet-delivered entries (pending, processing,
// or failed), newest bookkeeping included, for observability. It is tenant-scoped
// under RLS.
func (o *Outbox) Pending(ctx context.Context, tenantID string) ([]Record, error) {
	var out []Record
	now := o.clockNow()
	err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id::text, destination, payload, idempotency_key, status, attempts, COALESCE(last_error, ''),
			        (status = 'processing' AND lease_until IS NOT NULL AND lease_until > $2) AS lease_held
			   FROM outbox
			  WHERE tenant_id = $1 AND status <> 'delivered'
			  ORDER BY id`, tenantID, now)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r Record
			if err := rows.Scan(&r.ID, &r.TenantID, &r.Destination, &r.Payload,
				&r.IdempotencyKey, &r.Status, &r.Attempts, &r.LastError, &r.LeaseHeld); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// Get returns one outbox entry in its tenant context (RLS-enforced), exposing its
// retry state.
func (o *Outbox) Get(ctx context.Context, tenantID string, id int64) (Record, error) {
	var r Record
	err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, tenant_id::text, destination, payload, idempotency_key, status, attempts, COALESCE(last_error, '')
			   FROM outbox
			  WHERE tenant_id = $1 AND id = $2`, tenantID, id).
			Scan(&r.ID, &r.TenantID, &r.Destination, &r.Payload,
				&r.IdempotencyKey, &r.Status, &r.Attempts, &r.LastError)
	})
	return r, err
}

// circuitIdleRetention is how long a CLOSED circuit is kept after its last
// update before it is forgotten.
const circuitIdleRetention = time.Hour

// pruneIdleCircuitsLocked drops closed circuits that have been idle.
//
// The map is keyed by (tenant, destination) and nothing ever deleted from it, so
// it grew with every tenant-destination pair the deployment ever used and was
// then iterated IN FULL on every claim — the sweep got slower the longer the
// process ran. Forgetting a closed circuit is information-free: the claim path
// creates one on demand, and a missing key already means "closed". Open and
// half-open circuits are never pruned, because those DO carry state.
//
// Callers hold o.circuitMu.
func (o *Outbox) pruneIdleCircuitsLocked(now time.Time) {
	for key, circuit := range o.circuits {
		if circuit == nil {
			delete(o.circuits, key)
			continue
		}
		if circuit.state != CircuitClosed || circuit.failures != 0 {
			continue
		}
		if !circuit.updatedAt.IsZero() && now.Sub(circuit.updatedAt) >= circuitIdleRetention {
			delete(o.circuits, key)
		}
	}
}
