package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// This file holds the read-model snapshot persistence (SPINE-007 / EXC-SCALE-01).
// A snapshot is a per-tenant capture of the event-sourced read model together with
// the global event-stream offset it covers, so a cold boot or disaster restore can
// rehydrate the read model from the latest snapshot and replay ONLY the tail after
// it — turning startup from O(lifetime events) into O(events since the snapshot).
//
// The event log remains the source of truth (AN-2): a snapshot is purely an
// optimization, fully reconstructible by a Rebuild() from sequence 0, and a corrupt,
// missing, or unreadable snapshot is ignored in favor of a full replay. Nothing
// answers a query from a snapshot; the relational read model does. The snapshot only
// seeds that read model faster on boot.
//
// The capture and restore are schema-driven, not entity-typed: each read-model table
// is dumped with to_jsonb(row) and restored with jsonb_populate_recordset against the
// table's own row type, so every column (text[], timestamptz, jsonb, derived status
// columns like certificates.status/replaces_id) round-trips faithfully. This is why a
// snapshot reproduces the EXACT read model, including statuses that come from later
// events (revoked/superseded), without re-deriving them.

// SnapshotFormatVersion is the on-disk shape of a read-model snapshot payload
// (SPINE-007). It is stored on every snapshot row; a snapshot whose version the
// running code does not understand is ignored on restore (falling back to a full
// rebuild), so the blob shape can evolve without silently mis-decoding an old one.
const SnapshotFormatVersion = 1

// snapshotTables are the read-model tables captured in a per-tenant snapshot, in
// dependency order (parents before children) so a restore's inserts never trip a
// foreign key. It is exactly ReadModelTables minus the cross-tenant `tenants` row
// (which the boot restore re-seeds separately, like the rebuild path), arranged so
// owners precede the identities/certificates that reference them and
// identity_transitions (which references identities) comes last.
var snapshotTables = []string{"owners", "issuers", "identities", "certificates", "identity_transitions"}

// joinReadModel renders the read-model table list for a TRUNCATE, matching the set
// the rebuild path empties so a snapshot restore starts from the same clean slate.
func joinReadModel() string { return strings.Join(ReadModelTables, ", ") }

// ErrNoSnapshot is returned by LatestSnapshotOffset when no tenant has a snapshot
// yet, so the boot path knows to fall through to the existing checkpoint catch-up
// (or a full rebuild) rather than treating the absence as an error.
var ErrNoSnapshot = errors.New("store: no read-model snapshot")

// WriteTenantSnapshot captures tenant tenantID's current read-model rows and the
// global offset coveredSeq they are consistent as-of, replacing any prior snapshot
// for that tenant (SPINE-007). It runs under the tenant's RLS context (AN-1): the
// capture SELECTs and the snapshot UPSERT all filter on tenant_id, so a tenant's
// snapshot can only ever hold that tenant's rows. The capture and the write share
// one transaction, so the stored snapshot is a consistent point-in-time view.
//
// coveredSeq must be a sequence the read model has actually applied for this tenant
// (the caller passes the projection checkpoint at capture time); every event with
// sequence <= coveredSeq is reflected in the captured rows.
func (s *Store) WriteTenantSnapshot(ctx context.Context, tenantID string, coveredSeq uint64) error {
	if tenantID == "" {
		return fmt.Errorf("store: WriteTenantSnapshot requires a tenant id (AN-1)")
	}
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// Build a jsonb document {table: [row, ...], ...} entirely inside PostgreSQL so
		// the row encoding is the database's own (handles every column type), and it is
		// scoped to this tenant by the RLS context already set on tx.
		//
		// jsonb_agg over to_jsonb(t.*) yields the rows; coalesce to an empty array when
		// the table has none. The per-table sub-selects are assembled into one object.
		//trstctl:system-query — runs under the tenant's RLS context (WithTenant set the role + trstctl.tenant_id GUC), so FORCE-d row-level security confines every sub-select to THIS tenant's rows; the snapshot blob therefore holds only this tenant's data even though the SQL carries no literal tenant_id predicate (AN-1 enforced by RLS, not by the clause).
		const payloadSQL = `
SELECT jsonb_build_object(
  'owners',                (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM owners t),
  'issuers',               (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM issuers t),
  'identities',            (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM identities t),
  'certificates',          (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM certificates t),
  'identity_transitions',  (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM identity_transitions t)
)`
		var payload []byte
		if err := tx.QueryRow(ctx, payloadSQL).Scan(&payload); err != nil {
			return fmt.Errorf("store: capture snapshot payload: %w", err)
		}
		// Upsert the single per-tenant snapshot row. tenant_id is written explicitly and
		// the RLS WITH CHECK confirms it matches the GUC, so the row is this tenant's.
		_, err := tx.Exec(ctx,
			`INSERT INTO read_model_snapshots (tenant_id, covered_seq, format_version, payload, created_at)
			      VALUES ($1, $2, $3, $4, now())
			 ON CONFLICT (tenant_id) DO UPDATE
			      SET covered_seq = EXCLUDED.covered_seq,
			          format_version = EXCLUDED.format_version,
			          payload = EXCLUDED.payload,
			          created_at = now()`,
			tenantID, int64(coveredSeq), SnapshotFormatVersion, payload)
		if err != nil {
			return fmt.Errorf("store: write snapshot: %w", err)
		}
		return nil
	})
}

// LatestSnapshotOffset returns the LOWEST covered offset across all current
// snapshots in a known format — the watermark the boot restore resumes catch-up
// from after rehydrating from snapshots (SPINE-007). It is the minimum because the
// boot restore must replay every event any tenant is missing; resuming from the
// lowest covered offset guarantees no tenant's tail is skipped (replaying an event a
// tenant already has is an idempotent upsert). It returns ErrNoSnapshot when no
// known-format snapshot exists, so the caller falls through to the existing
// checkpoint catch-up. It is a system (RLS-bypassing) read.
func (s *Store) LatestSnapshotOffset(ctx context.Context) (uint64, error) {
	var min *int64
	// cross-tenant by design: the boot restore needs the LOWEST covered offset across
	// ALL tenants' snapshots so no tenant's tail is skipped (like the rebuild path).
	err := s.pool.QueryRow(ctx,
		//trstctl:system-query — cross-tenant min(covered_seq) over all tenants; runs on the pool, not under RLS (AN-1 exemption).
		`SELECT min(covered_seq) FROM read_model_snapshots WHERE format_version = $1`,
		SnapshotFormatVersion).Scan(&min)
	if err != nil {
		return 0, fmt.Errorf("store: read latest snapshot offset: %w", err)
	}
	if min == nil {
		return 0, ErrNoSnapshot
	}
	if *min < 0 {
		return 0, nil
	}
	return uint64(*min), nil
}

// RestoreSnapshotsTx truncates the event-sourced read model and reloads every
// tenant's snapshot rows into it on the caller's transaction (SPINE-007). It is the
// boot/DR rehydration primitive: after it returns, the read model holds exactly what
// the snapshots captured (as-of each tenant's covered offset), and the caller replays
// the tail after the lowest covered offset to bring it fully current.
//
// It runs as the owner (system) role on the rebuild's transaction — it must TRUNCATE
// and write every tenant's rows in one pass, exactly like RebuildReadModelTx — so RLS
// is bypassed; every INSERT carries tenant_id explicitly (the snapshot row's
// tenant_id), so AN-1 holds. Restoring is atomic with the truncate: a failure rolls
// back to the prior read model rather than leaving a half-loaded inventory.
//
// The `tenants` table is NOT restored here: the tail replay re-seeds it from
// tenant.registered events (and the boot path sets the checkpoint accordingly),
// matching how the rebuild path treats the tenants projection. Each per-table reload
// uses jsonb_populate_recordset against the table's own row type, so every column
// type (text[], timestamptz, jsonb, derived status columns) is reconstructed exactly.
func (s *Store) RestoreSnapshotsTx(ctx context.Context, tx pgx.Tx) (restored int, err error) {
	// 1) Empty the event-sourced read model (same set the rebuild truncates), so the
	// reload is a clean rehydration rather than an overlay on possibly-stale rows.
	if _, err := tx.Exec(ctx, `TRUNCATE `+joinReadModel()+` CASCADE`); err != nil {
		return 0, fmt.Errorf("store: truncate read model for snapshot restore: %w", err)
	}
	// 2) Load every known-format tenant snapshot, parents before children. We read all
	// snapshot payloads first (one query), then insert per tenant per table.
	// cross-tenant by design: the boot/DR restore rehydrates EVERY tenant's read model
	// in one pass (owner role, like RebuildReadModelTx); each tenant's rows are then
	// re-inserted under that tenant's id, so AN-1 holds even with RLS bypassed here.
	rows, err := tx.Query(ctx,
		//trstctl:system-query — cross-tenant read of all tenants' snapshots for the boot/DR restore; owner role, not under RLS (AN-1 exemption).
		`SELECT tenant_id, payload FROM read_model_snapshots WHERE format_version = $1 ORDER BY tenant_id`,
		SnapshotFormatVersion)
	if err != nil {
		return 0, fmt.Errorf("store: read snapshots for restore: %w", err)
	}
	type snap struct {
		tenantID string
		payload  []byte
	}
	var snaps []snap
	for rows.Next() {
		var sn snap
		if err := rows.Scan(&sn.tenantID, &sn.payload); err != nil {
			rows.Close()
			return 0, err
		}
		snaps = append(snaps, sn)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, sn := range snaps {
		// Set the tenant GUC so any tenant-scoped logic sees the right tenant during the
		// reload (the inserts themselves carry tenant_id explicitly; the owner role
		// bypasses RLS, exactly like the atomic rebuild).
		if _, err := tx.Exec(ctx, "SELECT set_config('trstctl.tenant_id', $1, true)", sn.tenantID); err != nil {
			return 0, fmt.Errorf("store: set tenant for snapshot restore: %w", err)
		}
		for _, table := range snapshotTables {
			// Insert the table's rows from the payload's per-table array using the table's
			// own row type, so every column is reconstructed with the correct type. The
			// `-> table` extracts that table's array; jsonb_populate_recordset(null::table,
			// arr) turns it into a typed rowset. A NULL/absent array yields no rows.
			// cross-tenant restore (owner role, like RebuildReadModelTx): rows come from
			// THIS tenant's snapshot blob, carry their own tenant_id, and the
			// trstctl.tenant_id GUC is set above, so each lands under the correct tenant.
			sql := fmt.Sprintf(
				//trstctl:system-query — cross-tenant snapshot reload into the read model; owner role, not under RLS; each row carries its tenant_id (AN-1 exemption).
				`INSERT INTO %s SELECT (jsonb_populate_recordset(NULL::%s, $1::jsonb -> $2)).*`,
				table, table)
			if _, err := tx.Exec(ctx, sql, sn.payload, table); err != nil {
				return 0, fmt.Errorf("store: restore snapshot rows into %s: %w", table, err)
			}
		}
		restored++
	}
	return restored, nil
}

// DeleteAllSnapshots removes every read-model snapshot (SPINE-007). It is used by an
// explicit Rebuild (the read model is re-derived from sequence 0, so any snapshot is
// stale relative to the rebuilt state and would mislead the next boot) and is
// available to operators/tests that want to force a full-replay boot to prove the log
// remains the source of truth. It is a system (RLS-bypassing) write.
func (s *Store) DeleteAllSnapshots(ctx context.Context) error {
	//trstctl:system-query — cross-tenant by design: a full Rebuild invalidates ALL tenants' snapshots at once (they are stale relative to the from-zero rebuild); runs on the pool, not under RLS (AN-1 exemption).
	if _, err := s.pool.Exec(ctx, `DELETE FROM read_model_snapshots`); err != nil {
		return fmt.Errorf("store: delete snapshots: %w", err)
	}
	return nil
}

// SnapshotCount returns how many read-model snapshots are currently stored. It backs
// tests asserting a snapshot was (or was not) written and lets the boot path log how
// many tenants it rehydrated. It is a system (RLS-bypassing) read.
func (s *Store) SnapshotCount(ctx context.Context) (int, error) {
	var n int
	//trstctl:system-query — cross-tenant by design: counts snapshots across ALL tenants (a fleet/boot diagnostic); runs on the pool, not under RLS (AN-1 exemption).
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM read_model_snapshots`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count snapshots: %w", err)
	}
	return n, nil
}
