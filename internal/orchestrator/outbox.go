package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// Message is one external call to perform, as recorded in the outbox. The
// dispatcher hands it to a Handler; the IdempotencyKey lets the receiver collapse
// at-least-once redeliveries to a single effect (the AN-5 ↔ AN-6 bridge).
type Message struct {
	TenantID       string
	Destination    string
	IdempotencyKey string
	Payload        []byte
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
	store       *store.Store
	backoff     func(attempts int) time.Duration
	maxAttempts int
}

// Option configures an Outbox.
type Option func(*Outbox)

// WithBackoff sets the delay before a failed entry becomes eligible for retry,
// as a function of the new attempt count.
func WithBackoff(f func(attempts int) time.Duration) Option {
	return func(o *Outbox) { o.backoff = f }
}

// WithMaxAttempts sets how many attempts an entry gets before it is dead-lettered
// (marked failed and no longer dispatched).
func WithMaxAttempts(n int) Option {
	return func(o *Outbox) { o.maxAttempts = n }
}

// NewOutbox returns an Outbox backed by the given store. By default it retries
// with a quadratic backoff and dead-letters after 10 attempts.
func NewOutbox(s *store.Store, opts ...Option) *Outbox {
	o := &Outbox{
		store:       s,
		backoff:     func(attempts int) time.Duration { return time.Duration(attempts*attempts) * time.Second },
		maxAttempts: 10,
	}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

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

// Dispatch performs all entries that are due now, one per transaction, and
// returns how many it attempted. A Handler failure is not a Dispatch error: it is
// recorded on the row (attempts, last_error, next_attempt_at) for a later retry,
// or dead-lettered once the attempt cap is reached. Only a database/transport
// fault aborts Dispatch.
//
// Entries scheduled into the future (a failed entry serving its backoff) and
// entries already handled in this run are skipped, so one Dispatch call drains
// the currently-due backlog without spinning on a zero-backoff failure.
func (o *Outbox) Dispatch(ctx context.Context, h Handler) (int, error) {
	cutoff := time.Now().UTC()
	seen := make(map[int64]bool)
	processed := 0
	for {
		id, claimed, err := o.dispatchOne(ctx, h, cutoff)
		if err != nil {
			return processed, err
		}
		if !claimed || seen[id] {
			break
		}
		seen[id] = true
		processed++
	}
	return processed, nil
}

// dispatchOne claims at most one due entry (FOR UPDATE SKIP LOCKED so concurrent
// dispatchers never grab the same row), delivers it, and records the outcome —
// all in one transaction. The claim and the result mark are atomic; if the
// process dies mid-delivery the transaction rolls back and the entry stays
// pending, to be redelivered (at-least-once).
func (o *Outbox) dispatchOne(ctx context.Context, h Handler, cutoff time.Time) (id int64, claimed bool, err error) {
	tx, err := o.store.SystemPool().Begin(ctx)
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var msg Message
	var attempts int
	err = tx.QueryRow(ctx,
		//trstctl:system-query — the dispatcher drains every tenant's due entries in one pass (no tenant predicate); the claimed row's tenant_id is read back and carried in the Message. Cross-tenant by design (AN-1 exemption).
		`SELECT id, tenant_id::text, destination, payload, idempotency_key, attempts
		   FROM outbox
		  WHERE status = 'pending' AND next_attempt_at <= $1
		  ORDER BY id
		  FOR UPDATE SKIP LOCKED
		  LIMIT 1`, cutoff).
		Scan(&id, &msg.TenantID, &msg.Destination, &msg.Payload, &msg.IdempotencyKey, &attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("orchestrator: claim outbox: %w", err)
	}

	attempts++
	if derr := h.Deliver(ctx, msg); derr != nil {
		status := "pending"
		if attempts >= o.maxAttempts {
			status = "failed"
		}
		next := time.Now().UTC().Add(o.backoff(attempts))
		if _, err := tx.Exec(ctx,
			`UPDATE outbox
			    SET attempts = $3, last_error = $4, next_attempt_at = $5, status = $6
			  WHERE id = $1 AND tenant_id = $2`,
			id, msg.TenantID, attempts, derr.Error(), next, status); err != nil {
			return 0, false, fmt.Errorf("orchestrator: record failure: %w", err)
		}
		return id, true, tx.Commit(ctx)
	}

	if _, err := tx.Exec(ctx,
		`UPDATE outbox
		    SET status = 'delivered', delivered_at = now(), attempts = $3, last_error = NULL
		  WHERE id = $1 AND tenant_id = $2`,
		id, msg.TenantID, attempts); err != nil {
		return 0, false, fmt.Errorf("orchestrator: record delivery: %w", err)
	}
	return id, true, tx.Commit(ctx)
}

// Pending returns the tenant's not-yet-delivered entries (pending or failed),
// newest bookkeeping included, for observability. It is tenant-scoped under RLS.
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
