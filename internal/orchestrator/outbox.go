package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

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
}

// Entry is a new outbox row to enqueue alongside a state change.
type Entry struct {
	TenantID       string
	Destination    string
	IdempotencyKey string
	Payload        []byte
}

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

// HandlerFunc adapts a function to a Handler.
type HandlerFunc func(ctx context.Context, m Message) error

// Deliver calls f.
func (f HandlerFunc) Deliver(ctx context.Context, m Message) error { return f(ctx, m) }

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
// destination. This prevents one down CA/connector/webhook from occupying every
// outbox worker.
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
	return floor + time.Duration(rand.Int63n(int64(span)+1))
}

func (o *Outbox) clockNow() time.Time { return o.now().UTC() }

// Enqueue records an outbox entry on the caller's transaction, so the intent is
// durable iff the state change it accompanies commits (AN-6). It returns the new
// entry's id.
func (o *Outbox) Enqueue(ctx context.Context, tx pgx.Tx, e Entry) (int64, error) {
	var id int64
	err := tx.QueryRow(ctx,
		`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id`,
		e.TenantID, e.Destination, e.Payload, e.IdempotencyKey).Scan(&id)
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
	tag, err := tx.Exec(ctx,
		`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key)
		 SELECT $1, $2, $3, $4
		 WHERE NOT EXISTS (
		     SELECT 1 FROM outbox WHERE tenant_id = $1 AND idempotency_key = $4
		 )`,
		e.TenantID, e.Destination, e.Payload, e.IdempotencyKey)
	if err != nil {
		return false, fmt.Errorf("orchestrator: enqueue-if-absent outbox: %w", err)
	}
	return tag.RowsAffected() > 0, nil
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
// round-robin by tenant and destination: each round claims at most one row per
// tenant and destination, then starts a new round if more due work remains.
func (o *Outbox) Dispatch(ctx context.Context, h Handler) (int, error) {
	cutoff := o.clockNow()
	seenTenants := make(map[string]bool)
	seenDestinations := make(map[string]bool)
	processed := 0
	for {
		claim, claimed, err := o.claimOne(ctx, cutoff, seenTenants, seenDestinations)
		if err != nil {
			return processed, err
		}
		if !claimed {
			if len(seenTenants) == 0 && len(seenDestinations) == 0 {
				break
			}
			seenTenants = make(map[string]bool)
			seenDestinations = make(map[string]bool)
			continue
		}

		seenTenants[claim.msg.TenantID] = true
		seenDestinations[claim.msg.Destination] = true
		processed++
		if err := o.finalizeClaim(ctx, claim, o.deliver(ctx, h, claim)); err != nil {
			return processed, err
		}
	}
	return processed, nil
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
func (o *Outbox) claimOne(ctx context.Context, cutoff time.Time, seenTenants, seenDestinations map[string]bool) (claimedOutboxEntry, bool, error) {
	tx, err := o.store.SystemPool().Begin(ctx)
	if err != nil {
		return claimedOutboxEntry{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	now := o.clockNow()
	blockedCircuitKeys, reservedHalfOpen := o.reserveHalfOpenProbes(now)
	if _, err := tx.Exec(ctx,
		//trstctl:system-query — lease recovery is a cross-tenant system worker path; expired processing rows are returned to the shared pending queue.
		`UPDATE outbox
		    SET status = 'pending', worker_id = NULL, lease_until = NULL
		  WHERE status = 'processing' AND lease_until <= $1`, now); err != nil {
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
		        AND o.tenant_id::text <> ALL($7::text[])
		        AND o.destination <> ALL($8::text[])
		        AND (o.tenant_id::text || chr(31) || o.destination) <> ALL($9::text[])
		        AND (
		            SELECT count(*)
		              FROM outbox p
		             WHERE p.status = 'processing'
		               AND p.destination = o.destination
		               AND p.lease_until > $2
		        ) < $3
		        AND (
		            SELECT count(*)
		              FROM outbox p
		             WHERE p.status = 'processing'
		               AND p.tenant_id = o.tenant_id
		               AND p.lease_until > $2
		        ) < $4
		        AND NOT EXISTS (
		            SELECT 1
		              FROM outbox older
		             WHERE older.status = 'pending'
		               AND older.next_attempt_at <= $1
		               AND older.tenant_id = o.tenant_id
		               AND older.destination = o.destination
		               AND (older.next_attempt_at, older.id) < (o.next_attempt_at, o.id)
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
		 RETURNING o.id, o.tenant_id::text, o.destination, o.payload, o.idempotency_key, o.attempts`,
		cutoff, now, o.maxInFlightPerDestination, o.maxInFlightPerTenant,
		o.workerID, leaseUntil, mapKeys(seenTenants), mapKeys(seenDestinations), blockedCircuitKeys).
		Scan(&claim.id, &claim.msg.TenantID, &claim.msg.Destination, &claim.msg.Payload, &claim.msg.IdempotencyKey, &claim.attempts)
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
	o.releaseUnclaimedHalfOpenProbes(reservedHalfOpen, circuitKey{tenantID: claim.msg.TenantID, destination: claim.msg.Destination}, now)
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
		status := "pending"
		if claim.attempts >= o.maxAttempts {
			status = "failed"
		}
		now := o.clockNow()
		next := now.Add(o.retryDelay(claim.attempts))
		tag, err := tx.Exec(ctx,
			`UPDATE outbox
			    SET last_error = $4,
			        next_attempt_at = $5,
			        status = $6,
			        worker_id = NULL,
			        lease_until = NULL
			  WHERE id = $1
			    AND tenant_id = $2
			    AND status = 'processing'
			    AND worker_id = $3`,
			claim.id, claim.msg.TenantID, o.workerID, deliverErr.Error(), next, status)
		if err != nil {
			return fmt.Errorf("orchestrator: record failure: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("orchestrator: finalize outbox failure: lease for row %d was lost", claim.id)
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		o.recordCircuitFailure(claim.msg, deliverErr, now)
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

func (o *Outbox) reserveHalfOpenProbes(now time.Time) ([]string, map[circuitKey]bool) {
	if o.circuitFailureThreshold <= 0 {
		return []string{}, nil
	}
	blocked := make([]string, 0, len(o.circuits))
	reserved := make(map[circuitKey]bool)
	var transitions []CircuitTransition

	o.circuitMu.Lock()
	for key, circuit := range o.circuits {
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
	key := circuitKey{tenantID: m.TenantID, destination: m.Destination}
	var transition *CircuitTransition

	o.circuitMu.Lock()
	circuit := o.circuits[key]
	if circuit == nil {
		circuit = &outboxCircuit{state: CircuitClosed}
		o.circuits[key] = circuit
	}
	from := circuit.state
	circuit.failures++
	circuit.lastError = err.Error()
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
	key := circuitKey{tenantID: m.TenantID, destination: m.Destination}
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
	err := o.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id::text, destination, payload, idempotency_key, status, attempts, COALESCE(last_error, '')
			   FROM outbox
			  WHERE tenant_id = $1 AND status <> 'delivered'
			  ORDER BY id`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r Record
			if err := rows.Scan(&r.ID, &r.TenantID, &r.Destination, &r.Payload,
				&r.IdempotencyKey, &r.Status, &r.Attempts, &r.LastError); err != nil {
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
