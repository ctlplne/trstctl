// Package outboxgc is the outbox retention sweep (SPINE-003): a system
// (cross-tenant) maintenance subsystem that bounds the outbox table so a
// high-volume fleet's one-row-per-external-effect growth cannot accumulate without
// limit. The outbox (AN-6) records every outbound call (upstream CA, connector,
// webhook, notification); on success the dispatcher marks the row delivered, but a
// delivered row is finished work and only needs to live for a short audit /
// observability window. Without a sweep those rows accumulated forever, so the
// table, its indexes, and every backup grew without bound and eventually required a
// manual cleanup/VACUUM.
//
// Like the idempotency-key GC (internal/idemgc) and the audit retention worker
// (internal/audit), this is a system maintenance task that operates across all
// tenants by design, so it runs on the connection pool directly rather than under a
// tenant's row-level-security context — it reclaims every tenant's eligible rows in
// one pass and reads no tenant data into the application. It therefore lives outside
// the repository layer (internal/store and the //trstctl:repository-marked
// orchestrator), whose AN-1 tenant-filter rule governs per-tenant data access, not
// deliberate system-wide retention.
//
// AN-6 (at-least-once delivery) is preserved: only rows whose status is already
// 'delivered' AND whose delivered_at is older than the window are reclaimed. Pending
// and failed rows (the dispatcher's work queue and the dead-letter trail) are never
// touched, so no undelivered effect is ever dropped and stuck/failed entries stay
// visible for operators.
package outboxgc

import (
	"context"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// DefaultRetention is how long a delivered outbox row is kept before the sweep
// reclaims it. A delivered row is finished work, kept only for a short audit /
// observability window, so a day comfortably covers operational inspection while
// keeping the table — and its backups — bounded for a high-volume fleet. The
// authoritative record of the effect lives in the event log and the receiver's
// idempotency ledger, not in the outbox row. It is the documented default; the
// control plane may override the window where the sweep is wired in.
const DefaultRetention = 24 * time.Hour

// Sweeper reclaims delivered outbox rows past the retention window. It holds the
// store so it can run the cross-tenant maintenance query on the pool (bypassing
// RLS, like the idempotency-key GC and the outbox dispatcher).
type Sweeper struct {
	store     *store.Store
	retention time.Duration
}

// New returns a Sweeper over s with the given retention window; a non-positive
// window uses DefaultRetention.
func New(s *store.Store, retention time.Duration) *Sweeper {
	if retention <= 0 {
		retention = DefaultRetention
	}
	return &Sweeper{store: s, retention: retention}
}

// Retention is the configured window.
func (w *Sweeper) Retention() time.Duration { return w.retention }

// Sweep deletes delivered outbox rows whose delivered_at is older than the
// retention window, returning how many rows it reclaimed (SPINE-003). The
// delivered_at partial index (migration 0020) makes the delete touch only the
// eligible tail, so reclamation stays cheap as the table grows. Pending and failed
// rows are never matched (status <> 'delivered'), so at-least-once delivery (AN-6)
// and the visibility of stuck/failed entries are preserved. It is safe to call
// concurrently and is idempotent: a second call right after reclaims nothing.
func (w *Sweeper) Sweep(ctx context.Context) (int64, error) {
	cutoff := time.Now().UTC().Add(-w.retention)
	tag, err := w.store.SystemPool().Exec(ctx,
		`DELETE FROM outbox
		  WHERE status = 'delivered' AND delivered_at IS NOT NULL AND delivered_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("outboxgc: sweep: %w", err)
	}
	return tag.RowsAffected(), nil
}

// Count returns the total number of outbox rows across all tenants. It backs the
// bound check (a test asserts the table stays bounded under the retention sweep) and
// operational introspection; like Sweep it is a system operation on the pool.
func (w *Sweeper) Count(ctx context.Context) (int64, error) {
	var n int64
	if err := w.store.SystemPool().QueryRow(ctx, "SELECT count(*) FROM outbox").Scan(&n); err != nil {
		return 0, fmt.Errorf("outboxgc: count: %w", err)
	}
	return n, nil
}
