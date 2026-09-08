// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"
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
	"discovery_coverage",
	"discovery_findings",
	"notification_reads",
	"notification_threshold_deliveries",
	"notification_delivery_receipts",
	"notification_test_operations",
	"discovery_runs",
	"discovery_schedules",
	"discovery_sources",
	"remediation_playbook_runs",
	"outbox_reconciliation_conflicts",
	"incident_fleet_reissuance_runs",
	"incident_executions",
	"pam_sessions",
	"compliance_report_schedules",
	"secret_rotation_schedule_tick_rows",
	"secret_rotation_schedule_ticks",
	"secret_rotation_schedule_scan_cursors",
	"secret_rotation_schedule_commands",
	"secret_rotation_schedules",
	"dynamic_secret_operations",
	"dynamic_secret_leases",
	"secret_sync_jobs",
	"managed_key_operations",
	"kubernetes_controller_posture",
	"managed_keys",
	"code_signing_operations",
	"access_change_request_decisions",
	"access_change_requests",
	"nhi_access_review_items",
	"nhi_access_review_campaigns",
	"pqc_migration_campaign_findings",
	"pqc_migration_campaigns",
	"privacy_archive_erasure_attestations",
	"privacy_retention_runs",
	"privacy_subject_erasure_preparations",
	"privacy_subject_erasure_operations",
	"privacy_subject_erasures",
	"connector_delivery_receipts",
	"lifecycle_rotation_runs",
	"certificates",
	"identity_transitions",
	"ownership_readiness_exceptions",
	"identities",
	"ca_ceremony_approvals",
	"ca_key_ceremonies",
	// AUD-77 exact approvals are event-sourced tenant data. Decisions carry a
	// composite FK to requests, so erase them first. The legacy pair below remains
	// independently backed-up history until its retention window ends.
	"operation_approval_decisions",
	"operation_approval_requests",
	"profile_edit_approvals",     // OPP-R09: parked profile create/edit approvals leave with the tenant
	"issuance_approvals",         // EXC-WIRE-03: FK -> issuance_approval_requests
	"issuance_approval_requests", // EXC-WIRE-03: served dual-control approval state
	// I3: the first-class request object. Tenant history — who asked for what,
	// who denied it and why — and it leaves with the tenant.
	"issuance_requests",
	// I4: both the collapsed diagnosis and its bounded event-id deduplication
	// window are tenant operational telemetry and leave with the tenant.
	"enrollment_diagnostic_observations",
	"enrollment_diagnostics",
	// AUD-52: exact delivery receipts reference their standing destination.
	"audit_feed_deliveries",
	"audit_feed_destinations",
	// AUD-58 Provider workforce authority uses the fixed zero-UUID Provider
	// partition, not a customer tenant. Keeping both tables in the exhaustive
	// tenant_id catalog makes that exception visible: a customer offboard runs
	// the normal tenant predicate and therefore deletes no global operator or
	// retained delegation evidence; the Provider authority event separately
	// revokes that customer's standing grants.
	"provider_operator_delegations",
	"provider_operators",
	// Independent tenant-scoped tables (no inbound RESTRICT foreign key).
	// I2: ownership disagreements reference an owner_id. Listed BEFORE owners so
	// the order stays correct if that reference ever becomes a real foreign key —
	// and because a conflict about an owner who no longer exists is not something
	// an offboarded tenant should leave behind.
	"owner_ownership_conflicts",
	// AUD-46: bounded CMDB source inventory is tenant operational evidence and
	// must leave before its schedule and matched owners.
	"cmdb_ci_inventory",
	// I2: a tenant's standing instruction to reconcile its own CMDB. It names
	// the tenant's instance and credential reference, so it leaves with the
	// tenant — and a schedule that outlived its tenant would keep dispatching
	// relay reads on behalf of an account that no longer exists.
	"cmdb_reconcile_schedules",
	// I3: the ticket intake, for the same reason — a schedule that outlived
	// its tenant would keep reading an ITSM for an account that is gone.
	"ticket_intake_schedules",
	// B6: the edge sub-CA ledger. Issuances reference their delegation and
	// delegations their segment policy only logically (no FKs), but erase
	// leaf-first anyway so a partial failure never leaves issuance rows whose
	// delegation is gone.
	"edge_issuances",
	"edge_delegations",
	"edge_segment_policies",
	// F4: the AD CS certificate-database summary, a per-CA projection.
	"adcs_ca_databases",
	// Asset overrides reference owners through a composite tenant FK.
	"ownership_assignments",
	"owners",
	"issuers",
	"deployment_target_revisions",
	"deployment_targets",
	"agent_cert_revocations",
	// A5: staged upgrade campaigns and their dispatch ledger are the tenant's
	// own rollout history.
	"agent_upgrade_campaigns",
	"agent_upgrade_dispatches",
	// I5: the tenant's MDM poll instruction and device correlations leave
	// with the tenant.
	"mdm_poll_schedules",
	"agents",
	"agent_bootstrap_tokens",
	// A3: the credential-redemption ledger. It holds no credential values, but
	// it does record which agent redeemed which job attempt and when — tenant
	// history that must leave with the tenant.
	"agent_job_credential_redemptions",
	// A1: the signed receipt ledger. Statements and signatures are public
	// material, but they name the tenant's agents and the work they did, which
	// is tenant history and must leave with the tenant.
	"agent_job_receipts",
	// C3: declared segments. An operator's own description of the networks
	// they own is tenant data and leaves with the tenant.
	"discovery_segments",
	// F1: AD CS template posture is a tenant's own directory observation and
	// leaves with the tenant.
	"adcs_template_posture",
	"adcs_enrollment_service_posture",
	"policy_bindings",
	"tenant_members",
	"api_tokens",
	"machine_sessions",
	"machine_auth_method_overrides",
	"ca_authorities",
	"ca_issued_certs",
	"ca_crls",
	"ca_ocsp_responders",
	"ssh_keys",
	"ct_watched_domains",
	"ct_log_checkpoints",
	"crypto_assets",
	"credentials",
	"certificate_profiles",
	"secret_sync_workload_identity_sources",
	"workload_attester_trust_sources",
	"acme_dns01_provider_configs",
	"acme_upstream_authorizations",
	"endpoint_verifications",
	"revocation_endpoint_health",
	// H2: a migration run is the tenant's event-projected trust-wave state. It
	// has no child foreign keys, but it still must leave with the tenant and be
	// deleted before the tenant row during an offboard/rebuild.
	"migration_runs",
	// I5: the MDM device join. It names the tenant's own devices and leaves
	// with the tenant.
	"mdm_device_correlations",
	"mdm_scep_policies",
	"audit_checkpoints",
	"notification_channels",
	"notification_routing_policies",
	"secret_shares",
	"approved_target_event_fences",
	"application_secret_mutation_fences",
	"application_secret_tenant_epochs",
	"application_secret_mutation_receipts",
	"secret_store_versions",
	"secret_store",
	"read_model_snapshots",
	"tenant_key_domains",
	// Operational/system tenant-scoped tables.
	"browser_sessions",
	"idempotency_keys",
	"outbox",
	"rate_limits",
	// The tenant's own identity row, last.
	// L3: the tenant's white-label brand. It leaves with the tenant — a brand
	// row outliving its tenant would keep claiming a custom domain nobody owns.
	"tenant_branding",
	// L4: the tenant's silo placement and residency zone. It leaves with the
	// tenant — a placement row outliving its tenant would keep asserting a
	// residency guarantee for an account that no longer exists.
	"tenant_silos",
	// L2: the provider plane's own billing record for this tenant. Not
	// tenant-readable (a tenant must not see or edit the meter that bills them),
	// but it is about this tenant and must leave when they do.
	"provider_usage_meters",
	"provider_usage_coverage",
	"provider_tenant_quotas",
	// L3: the provider's durable registry rows for this customer. The
	// break-glass grants reference the customer's id; both leave with the
	// tenant, and the registry row is the provider-plane analogue of the core
	// `tenants` row deleted last.
	"provider_breakglass_grants",
	"provider_tenants",
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

// TenantSecretSyncNotQuiescentError identifies receiver authority that can still
// write stale bytes after local deletion. Lease expiry is deliberately absent:
// once a generation crossed the receiver boundary, only exact single-generation
// terminal evidence proves that no older call can finish later.
type TenantSecretSyncNotQuiescentError struct {
	TenantID         string
	TenantEpoch      string
	JobID            string
	OutboxID         int64
	ReceiverIOStarts int64
	Reason           string
}

func (e *TenantSecretSyncNotQuiescentError) Error() string {
	if e == nil {
		return "store: tenant secret-sync receiver is not quiescent"
	}
	return fmt.Sprintf(
		"store: tenant %s secret-sync receiver is not quiescent (epoch=%s job=%s outbox=%d starts=%d): %s",
		e.TenantID, e.TenantEpoch, e.JobID, e.OutboxID, e.ReceiverIOStarts, e.Reason,
	)
}

type tenantSecretSyncEffectAuthority struct {
	outboxID         int64
	destination      string
	status           string
	targetOrder      int64
	receiverIOStarts int64
}

// PreflightTenantOffboardTx acquires the exclusive lifecycle fence before the
// tenant row, then proves every effect_possible receiver is an exact delivered
// command with one and only one receiver generation. Orphaned or malformed
// authority is itself unsafe: deleting it would erase the only warning that an
// external write may still finish.
func (s *Store) PreflightTenantOffboardTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	if tenantID == "" {
		return fmt.Errorf("store: tenant offboard preflight requires a tenant id")
	}
	// This is the first callback statement. A direct caller may already hold the
	// backup fence through WithTenant, so blocking behind the privacy operation's
	// exclusive grant would invert the global order and deadlock its cutover.
	var privacyOperationShared bool
	if err := tx.QueryRow(ctx,
		`SELECT pg_try_advisory_xact_lock_shared($1)`,
		HistoryRewriteOperationAdvisoryLockKey).Scan(&privacyOperationShared); err != nil {
		return fmt.Errorf("store: test privacy operation fence before offboard: %w", err)
	}
	if !privacyOperationShared {
		return ErrPrivacyHistoryOperationActive
	}
	if _, err := lockTenantRegistrationForOffboardTx(ctx, tx, tenantID); err != nil {
		return err
	}
	preparationActive, err := hasPrivacySubjectErasurePreparationTx(ctx, tx, tenantID)
	if err != nil {
		return fmt.Errorf("store: inspect privacy erasure preparation before offboard: %w", err)
	}
	if preparationActive {
		return ErrPrivacySubjectErasurePreparationActive
	}
	rows, err := tx.Query(ctx, `
		SELECT id, destination, status, COALESCE(secret_sync_target_order, 0),
		       secret_sync_receiver_io_starts
		  FROM outbox
		 WHERE tenant_id = $1
		   AND secret_sync_receiver_effect_state = 'effect_possible'
		 ORDER BY id
		 FOR UPDATE`, tenantID)
	if err != nil {
		return fmt.Errorf("store: inspect tenant secret-sync receiver authority: %w", err)
	}
	var authorities []tenantSecretSyncEffectAuthority
	for rows.Next() {
		var authority tenantSecretSyncEffectAuthority
		if err := rows.Scan(&authority.outboxID, &authority.destination, &authority.status,
			&authority.targetOrder, &authority.receiverIOStarts); err != nil {
			rows.Close()
			return err
		}
		authorities = append(authorities, authority)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	for _, authority := range authorities {
		var (
			tenantEpoch    string
			jobID          string
			status         SecretSyncJobStatus
			target         string
			jobOutboxID    int64
			jobTargetOrder int64
		)
		// Migration 0153 deliberately revoked UPDATE on secret_sync_jobs from
		// trstctl_app so a request path cannot forge terminal evidence. PostgreSQL
		// also requires UPDATE privilege for SELECT ... FOR UPDATE, so this one
		// owner-backed lifecycle preflight must briefly leave the application role
		// to lock the evidence row. The explicit tenant/outbox predicate remains the
		// AN-1 boundary, and the role is restored before any caller work continues.
		if _, err := tx.Exec(ctx, "RESET ROLE"); err != nil {
			return fmt.Errorf("store: offboard assume owner for secret-sync receiver preflight: %w", err)
		}
		err := tx.QueryRow(ctx, `
			SELECT tenant_epoch, id, status, target, outbox_id, target_order
			  FROM secret_sync_jobs
			 WHERE tenant_id = $1 AND outbox_id = $2
			 ORDER BY id
			 LIMIT 1
			 FOR UPDATE`, tenantID, authority.outboxID).Scan(
			&tenantEpoch, &jobID, &status, &target, &jobOutboxID, &jobTargetOrder,
		)
		if _, roleErr := tx.Exec(ctx, "SET LOCAL ROLE "+appRole); roleErr != nil {
			return fmt.Errorf("store: offboard restore application role after secret-sync receiver preflight: %w", roleErr)
		}
		reason := ""
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			reason = "effect_possible outbox has no exact projected job"
		case err != nil:
			return fmt.Errorf("store: load tenant secret-sync receiver job: %w", err)
		case jobOutboxID != authority.outboxID || jobTargetOrder != authority.targetOrder ||
			authority.destination != "secret.sync."+target:
			reason = "effect_possible job/outbox identity is malformed"
		case authority.status != "delivered":
			reason = "receiver outbox has no exact delivered terminal receipt"
		case status == SecretSyncJobPending:
			reason = "receiver generation has no terminal event"
		case status != SecretSyncJobDelivered:
			reason = "effect_possible authority is incompatible with terminal job status"
		case authority.receiverIOStarts != 1:
			reason = "multiple receiver generations may complete out of order"
		}
		if reason != "" {
			return &TenantSecretSyncNotQuiescentError{
				TenantID: tenantID, TenantEpoch: tenantEpoch, JobID: jobID,
				OutboxID: authority.outboxID, ReceiverIOStarts: authority.receiverIOStarts,
				Reason: reason,
			}
		}
	}
	return nil
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
// read model does not resurrect a deleted tenant. Object-store audit-archive residue
// (cold-storage bundles) is out of band and is documented in docs/limitations.md as
// operator-driven cleanup.
func (s *Store) OffboardTenant(ctx context.Context, tenantID string) (TenantDeletionAttestation, error) {
	att := newTenantDeletionAttestation(tenantID)
	if tenantID == "" {
		// Fail closed: under RLS an empty tenant id makes the policy GUC NULL, so a
		// DELETE would match no rows and silently "succeed" — exactly the fail-open we
		// must not allow for a deletion path (TENANT-003 sibling).
		return att, fmt.Errorf("store: OffboardTenant requires a tenant id (AN-1)")
	}

	err := s.WithPrivacyRecoveryBarrier(ctx, tenantID, "tenant offboard", func(barrierCtx context.Context) error {
		return s.WithTenant(barrierCtx, tenantID, func(tx pgx.Tx) error {
			var err error
			att, err = s.OffboardTenantTx(barrierCtx, tx, tenantID)
			return err
		})
	})
	return att, err
}

// ProjectTenantOffboard is the replay/tail form used when the caller may already
// own the event-history read barrier. It must not acquire the privacy operation
// lock outside that history grant (the inverse order can deadlock a cutover).
// OffboardTenantTx instead tries the shared operation xact lock before its first
// lifecycle statement and fails fast while a privacy rewrite owns the exclusive
// side; the durable marker check closes the crashed-writer window.
func (s *Store) ProjectTenantOffboard(
	ctx context.Context,
	tenantID string,
) (TenantDeletionAttestation, error) {
	att := newTenantDeletionAttestation(tenantID)
	if tenantID == "" {
		return att, fmt.Errorf("store: ProjectTenantOffboard requires a tenant id (AN-1)")
	}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		att, err = s.OffboardTenantTx(ctx, tx, tenantID)
		return err
	})
	return att, err
}

func newTenantDeletionAttestation(tenantID string) TenantDeletionAttestation {
	return TenantDeletionAttestation{
		TenantID: tenantID,
		Deleted:  make(map[string]int, len(TenantScopedTables)),
		Residue:  make(map[string]int),
	}
}

// OffboardTenantTx performs the guarded relational erase on the caller's tenant
// transaction. Live event emitters use this form so the preflight, immutable
// event append, and core deletion share one lifecycle fence and one SQL commit.
func (s *Store) OffboardTenantTx(ctx context.Context, tx pgx.Tx, tenantID string) (TenantDeletionAttestation, error) {
	att := newTenantDeletionAttestation(tenantID)
	if tenantID == "" {
		return att, fmt.Errorf("store: OffboardTenantTx requires a tenant id (AN-1)")
	}
	if err := s.PreflightTenantOffboardTx(ctx, tx, tenantID); err != nil {
		return att, err
	}
	for _, table := range TenantScopedTables {
		if table == "secret_rotation_schedule_tick_rows" ||
			table == "secret_rotation_schedule_ticks" ||
			table == "secret_rotation_schedule_commands" ||
			table == "secret_rotation_schedule_scan_cursors" {
			// Tick/command receivers and fair-scan cursors intentionally survive
			// read-model truncation and trstctl_app cannot DELETE them. Tenant
			// offboarding is the one broad erase path: temporarily return this
			// owner-backed transaction to its session role, delete only the explicit
			// tenant, then immediately restore the RLS application role.
			if _, err := tx.Exec(ctx, "RESET ROLE"); err != nil {
				return att, fmt.Errorf("store: offboard assume owner for %s: %w", table, err)
			}
			tag, err := tx.Exec(ctx,
				"DELETE FROM "+table+" WHERE tenant_id = $1", tenantID)
			if err != nil {
				return att, fmt.Errorf("store: offboard delete from %s: %w", table, err)
			}
			if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+appRole); err != nil {
				return att, fmt.Errorf("store: offboard restore application role: %w", err)
			}
			n := int(tag.RowsAffected())
			att.Deleted[table] = n
			att.Total += n
			continue
		}
		// RLS confines this DELETE to tenantID; the redundant explicit predicate is
		// defense-in-depth and documents intent. Identifiers come only from the
		// constant TenantScopedTables list.
		tag, err := tx.Exec(ctx,
			"DELETE FROM "+table+" WHERE tenant_id = $1", tenantID)
		if err != nil {
			return att, fmt.Errorf("store: offboard delete from %s: %w", table, err)
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
			return att, fmt.Errorf("store: offboard verify %s: %w", table, err)
		}
		if remaining != 0 {
			att.Residue[table] = remaining
			return att, fmt.Errorf("store: offboard incomplete: %d row(s) remain in %s for tenant %s", remaining, table, tenantID)
		}
	}
	att.Complete = true
	return att, nil
}
