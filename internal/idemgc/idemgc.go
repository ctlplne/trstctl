// Package idemgc is the idempotency-key retention sweep (SPINE-002): a system
// (cross-tenant) maintenance subsystem that bounds the idempotency_keys table so a
// high-volume fleet's one-row-per-served-mutation growth cannot accumulate without
// limit, and so completed keys/results are not retained indefinitely.
//
// Like the audit retention worker (internal/audit), this is a system maintenance
// task that operates across all tenants by design, so it runs on the connection
// pool directly rather than under a tenant's row-level-security context — it
// reclaims every tenant's expired rows in one pass and reads no tenant data into
// the application. It therefore lives outside the repository layer (internal/store
// and the //trstctl:repository-marked orchestrator), whose AN-1 tenant-filter
// rule governs per-tenant data access, not deliberate system-wide retention.
//
// AN-5 is preserved within the retention window: a retried mutation that arrives
// before its key expires still finds the cached result, because only keys whose
// completed_at is older than the window are reclaimed. Pending (in-flight) claims
// (completed_at IS NULL) are never touched, so an operation still running is never
// disturbed.
package idemgc

import (
	"context"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/store"
)

// DefaultRetention is how long a completed idempotency key is kept before the
// sweep reclaims it. It must comfortably exceed any client's retry horizon so AN-5
// holds within the window; seven days dwarfs realistic retry/backoff horizons
// (seconds to hours) while keeping the table — and its backups — bounded for a
// high-volume fleet. It is the documented default; the control plane may override
// the window where the sweep is wired in.
const DefaultRetention = 7 * 24 * time.Hour

// Sweeper reclaims expired idempotency keys. It holds the store so it can run the
// cross-tenant maintenance query on the pool (bypassing RLS, like the audit
// retention prune).
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

// Sweep deletes completed idempotency keys whose completed_at is older than the
// retention window, returning how many rows it reclaimed (SPINE-002). The
// completed_at partial index (migration 0018) makes the delete touch only the
// eligible tail, so reclamation stays cheap as the table grows. It is safe to call
// concurrently and is idempotent: a second call right after reclaims nothing.
func (w *Sweeper) Sweep(ctx context.Context) (int64, error) {
	cutoff := time.Now().UTC().Add(-w.retention)
	tag, err := w.store.SystemPool().Exec(ctx,
		`DELETE FROM idempotency_keys
		  WHERE completed_at IS NOT NULL AND completed_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("idemgc: sweep: %w", err)
	}
	return tag.RowsAffected(), nil
}

// Count returns the total number of idempotency keys across all tenants. It backs
// the bound check (a test asserts the table stays bounded under the retention
// sweep) and operational introspection; like Sweep it is a system operation on the
// pool.
func (w *Sweeper) Count(ctx context.Context) (int64, error) {
	var n int64
	if err := w.store.SystemPool().QueryRow(ctx, "SELECT count(*) FROM idempotency_keys").Scan(&n); err != nil {
		return 0, fmt.Errorf("idemgc: count: %w", err)
	}
	return n, nil
}
