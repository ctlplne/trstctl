package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// TenantScopedTables is the authoritative, ordered list of every tenant-scoped
// table OffboardTenant erases (TENANT-002). Order matters: a child that holds a
// foreign key into another tenant table is listed before its parent, so a
// RESTRICT foreign key never blocks the erase (e.g. attestations -> identities ->
// owners/issuers; certificates -> owners; ca_ceremony_approvals -> ceremonies).
// The tenant's own row in `tenants` is deleted last, after all rows that belong
// to it are gone.
//
// AN-1: every entry carries tenant_id and is confined by a FORCE-d
// USING (tenant_id = GUC) row-level-security policy, so OffboardTenant can delete
// from each one under Store.WithTenant and reach only the offboarded tenant's
// rows. A new tenant-scoped table MUST be added here (and to the read-model/backup
// classification) or its rows would survive an offboarding — the offboarding
// completeness test (internal/store offboarding suite / the projections two-tenant
// test) guards that this set stays in sync with the schema.
var TenantScopedTables = []string{
	// Children first (foreign keys point "up" to the tables below them).
	"attestations",
	"discovery_findings",
	"discovery_runs",
	"discovery_schedules",
	"discovery_sources",
	"incident_executions",
	"privacy_subject_erasures",
	"connector_delivery_receipts",
	"lifecycle_rotation_runs",
	"certificates",
	"identity_transitions",
	"identities",
	"ca_ceremony_approvals",
	"ca_key_ceremonies",
	"issuance_approvals",         // EXC-WIRE-03: FK -> issuance_approval_requests
	"issuance_approval_requests", // EXC-WIRE-03: served dual-control approval state
	// Independent tenant-scoped tables (no inbound RESTRICT foreign key).
	"owners",
	"issuers",
	"deployment_targets",
	"agents",
	"agent_bootstrap_tokens",
	"policy_bindings",
	"tenant_members",
	"api_tokens",
	"ca_authorities",
	"ca_issued_certs",
	"ca_crls",
	"ssh_keys",
	"ct_watched_domains",
	"ct_log_checkpoints",
	"crypto_assets",
	"credentials",
	"certificate_profiles",
	"audit_checkpoints",
	"secret_store",
	"read_model_snapshots",
	// Operational/system tenant-scoped tables.
	"idempotency_keys",
	"outbox",
	"rate_limits",
	// The tenant's own identity row, last.
	"tenants",
}

// TenantDeletionAttestation is the proof-of-erasure OffboardTenant returns: the
// number of rows deleted from each tenant-scoped table, the grand total, and the
// (post-delete, re-counted) residue per table — which a complete erase leaves at
// zero everywhere. It is the record an operator keeps to attest a contractual
// data-deletion / right-to-erasure request was honored. It carries no secret
// material (counts only), so it is safe to log and to project into an audit event.
type TenantDeletionAttestation struct {
	TenantID string         `json:"tenant_id"`
	Deleted  map[string]int `json:"deleted"`  // table -> rows deleted
	Total    int            `json:"total"`    // sum of Deleted
	Residue  map[string]int `json:"residue"`  // table -> rows still present after the delete (all 0 on success)
	Complete bool           `json:"complete"` // true iff every table's residue is 0
}

// OffboardTenant erases every tenant-scoped row for tenantID and returns a
// deletion attestation (TENANT-002). It is the data-retention / right-to-erasure
// primitive enterprise procurement requires: after it returns Complete, the
// tenant's certificates, sealed secrets, SSH keys, inventory, CA state, audit
// checkpoints, and operational rows are gone from PostgreSQL.
//
// It runs in a single transaction under the tenant's RLS context
// (Store.WithTenant), so every DELETE is confined to this tenant by the same
// FORCE-d USING (tenant_id = GUC) policy that confines a read — it is safe by
// construction and can never delete another tenant's rows (AN-1). After deleting,
// it re-counts each table in the same transaction and FAILS CLOSED (returns an
// error, rolling the whole erase back) if any tenant-scoped row survives, so a
// partial erase is never reported as complete. An empty tenantID is rejected
// (RLS would make the GUC NULL and silently match nothing — a fail-open we
// refuse, mirroring TENANT-003).
//
// AN-2 note: this is the relational erase. The event log is the source of truth;
// the caller emits a `tenant.offboarded` event (projections.EventTenantOffboarded)
// in the same flow so the offboarding is itself event-sourced and reconstructable,
// and the projector replays it through OffboardTenant on a Rebuild so a rebuilt
// read model does not resurrect a deleted tenant. Object-store audit-archive
// residue (cold-storage bundles) is out of band and is documented in
// docs/limitations.md as operator-driven cleanup.
func (s *Store) OffboardTenant(ctx context.Context, tenantID string) (TenantDeletionAttestation, error) {
	att := TenantDeletionAttestation{
		TenantID: tenantID,
		Deleted:  make(map[string]int, len(TenantScopedTables)),
		Residue:  make(map[string]int),
	}
	if tenantID == "" {
		// Fail closed: under RLS an empty tenant id makes the policy GUC NULL, so a
		// DELETE would match no rows and silently "succeed" — exactly the fail-open we
		// must not allow for a deletion path (TENANT-003 sibling).
		return att, fmt.Errorf("store: OffboardTenant requires a tenant id (AN-1)")
	}

	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		for _, table := range TenantScopedTables {
			// RLS confines this DELETE to tenantID; the redundant explicit predicate is
			// defense-in-depth and documents intent. (Identifiers are from the
			// constant TenantScopedTables, never user input, so the interpolation is
			// safe.)
			tag, err := tx.Exec(ctx,
				"DELETE FROM "+table+" WHERE tenant_id = $1", tenantID)
			if err != nil {
				return fmt.Errorf("store: offboard delete from %s: %w", table, err)
			}
			n := int(tag.RowsAffected())
			att.Deleted[table] = n
			att.Total += n
		}

		// Verification pass: in the same transaction (and same tenant RLS context),
		// confirm nothing tenant-scoped survives. If any row remains, fail closed so
		// the whole erase rolls back rather than being attested as complete.
		for _, table := range TenantScopedTables {
			var remaining int
			if err := tx.QueryRow(ctx,
				"SELECT count(*) FROM "+table+" WHERE tenant_id = $1", tenantID).Scan(&remaining); err != nil {
				return fmt.Errorf("store: offboard verify %s: %w", table, err)
			}
			if remaining != 0 {
				att.Residue[table] = remaining
				return fmt.Errorf("store: offboard incomplete: %d row(s) remain in %s for tenant %s", remaining, table, tenantID)
			}
		}
		att.Complete = true
		return nil
	})
	if err != nil {
		return att, err
	}
	return att, nil
}
