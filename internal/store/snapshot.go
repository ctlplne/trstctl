// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
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
// Bumped to 11 when the upstream authorization read model joined the snapshot
// set (epic B7). The bump is not cosmetic: a version-10 snapshot was taken
// before that table existed, so its covered offset already skips every
// observation event. Restoring it and resuming from that offset would leave the
// table permanently empty while the boot considered itself caught up — and an
// empty staleness surface reads as "nothing is stale", the one conclusion it
// must never invite falsely.
// Bumped to 12 when the endpoint verification read model joined the snapshot
// set (epic D2). A version-11 snapshot predates that table, so its covered
// offset already skips every verification observation; restoring one and
// resuming would leave the estate showing no verification state at all while
// boot considered itself caught up — and "no divergences recorded" reads as
// "nothing is wrong".
// Bumped to 13 when EIGHT tables that were truncated by restore but never
// reloaded joined the snapshot set: tenant_members, ca_authorities,
// agent_cert_revocations, and the I2/I3/I5/A5 projections. A v12 snapshot's
// payload carries none of them, so restoring one would empty all eight while
// the covered offset skipped their history. The class is now closed by
// TestEveryTruncatedReadModelTableIsRestoredBySnapshots rather than by
// remembering to update two lists.
// Bumped to 14 when the I5 MDM poll schedule joined the read model and the
// snapshot set together — the pairing the class-closing test now enforces.
// Bumped to 15 when the I3 ticket intake schedule did the same, 16 for the B6
// edge delegation projections, and 17 for the F4 AD CS database summary.
// Bumped to 18 when I4 enrollment diagnostics and their bounded event-id
// deduplication window became tenant-scoped read-model projections. A v17
// snapshot has neither table, so resuming after its covered sequence would
// otherwise turn "not restored" into the reassuring-looking empty state.
// Bumped to 19 when discovery findings gained recorded_ids. A v18 snapshot has
// no legacy-ID aliases; restoring it and skipping its covered history would make
// a later discovery.finding.triage_changed event unable to resolve the historical
// payload ID after AUD-96 canonicalized a duplicated natural key.
// Bumped to 20 when AUD-97 added tenant-visible outbox reconciliation conflict
// incidents. A v19 snapshot predates that projection, so resuming after its
// covered sequence would hide a quarantined receiver command from operators.
// Bumped to 21 for the single AUD-77/AUD-109 artifact. AUD-77 replaced standing
// approval tuples with event-sourced exact requests/decisions; AUD-109 added an
// immutable tenant+target order to secret-sync jobs. A v20 snapshot has neither
// the approval projections nor target_order, so accepting it would erase reviewer
// authority or make same-target receiver replay order unknowable.
// Bumped to 22 when snapshot capture became an all-tenant generation. Every row
// now carries the exact capture ID, projection head, tenant count, and digest of
// the sorted tenant IDs. A v21 row cannot prove that a privacy-erased tenant's row
// was not deleted while another tenant's positive offset survived, so it is never
// allowed to move a cold restore above sequence zero.
// Bumped to 23 when AD CS template posture became a real immutable-event
// projection. A v22 snapshot cannot carry that table and therefore must not skip
// the inventory observation events that rebuild it.
const SnapshotFormatVersion = 23

const snapshotSetPayloadKey = "_trstctl_snapshot_set"

// snapshotSetMetadata is copied into every tenant payload written by one complete
// capture. The tenant IDs themselves stay in their tenant rows; only their
// domain-separated digest is repeated. Restore recomputes that digest from the
// rows it can actually see, which makes a deleted or partially written set
// unusable instead of letting a neighbor's positive offset skip missing history.
type snapshotSetMetadata struct {
	ID              string `json:"id"`
	CoveredSequence uint64 `json:"covered_seq"`
	TenantCount     int    `json:"tenant_count"`
	TenantSetSHA256 string `json:"tenant_set_sha256"`
}

type completeSnapshotSet struct {
	metadata  snapshotSetMetadata
	tenantIDs []string
}

type snapshotSetQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

// snapshotTables are the read-model tables captured in a per-tenant snapshot, in
// dependency order (parents before children) so a restore's inserts never trip a
// foreign key. It is exactly ReadModelTables minus the cross-tenant `tenants` row
// (which the boot restore re-seeds separately, like the rebuild path), arranged so
// owners precede the identities/certificates that reference them and
// identity_transitions (which references identities) comes last. The revocation
// responder tables have no foreign keys, but they are pure projections too, so
// snapshots carry them with the rest of the tenant read model.
var snapshotTables = []string{"owners", "issuers", "certificate_profiles", "acme_dns01_provider_configs", "acme_upstream_authorizations", "endpoint_verifications", "mdm_scep_policies", "workload_attester_trust_sources", "secret_sync_workload_identity_sources", "tenant_key_domains", "identities", "certificates", "crypto_assets", "pqc_migration_campaigns", "pqc_migration_campaign_findings", "agents", "kubernetes_controller_posture", "ca_key_ceremonies", "ca_ceremony_approvals", "ca_issued_certs", "ca_crls", "ca_ocsp_responders", "discovery_sources", "discovery_schedules", "discovery_runs", "discovery_findings", "discovery_coverage", "notification_channels", "notification_reads", "notification_threshold_deliveries", "notification_test_operations", "notification_delivery_receipts", "connector_delivery_receipts", "lifecycle_rotation_runs", "outbox_reconciliation_conflicts", "incident_executions", "incident_fleet_reissuance_runs", "remediation_playbook_runs", "pam_sessions", "compliance_report_schedules", "secret_rotation_schedules", "dynamic_secret_operations", "dynamic_secret_leases", "secret_sync_jobs", "managed_key_operations", "managed_keys", "code_signing_operations", "privacy_subject_erasures", "privacy_retention_runs", "privacy_archive_erasure_attestations", "nhi_access_review_campaigns", "nhi_access_review_items", "access_change_requests", "access_change_request_decisions", "machine_sessions", "machine_auth_method_overrides", "identity_transitions",
	// Format 13. EIGHT tables sat in ReadModelTables without entering this
	// list or the capture payload — and the restore truncates the WHOLE read
	// model, then reloads only what snapshots carry, so any restore erased
	// them while boot considered itself caught up past their events. Five are
	// recent (I2/I3/I5/A5); tenant_members, ca_authorities and
	// agent_cert_revocations were older, found by the class-closing test
	// rather than by anyone reading lists. The version bump is what protects
	// existing deployments: a v12 snapshot's payload does not contain these
	// tables, and restoring one would wipe them again. ca_authorities is
	// captured ordered by (created_at, id) because it references itself
	// (parent_id, replaces_id) and both always point at strictly older rows,
	// so creation order is insertion-safe.
	"tenant_members", "ca_authorities", "agent_cert_revocations",
	"owner_ownership_conflicts", "cmdb_reconcile_schedules", "issuance_requests",
	"mdm_device_correlations", "agent_upgrade_campaigns", "agent_upgrade_dispatches",
	// Format 14: the I5 poll schedule joined ReadModelTables, so it must join
	// the snapshot set in the same change — the class test enforces exactly
	// this pairing now.
	"mdm_poll_schedules",
	// Format 15: the I3 ticket intake, same pairing.
	"ticket_intake_schedules",
	// Format 16: the B6 edge sub-CA read models, same pairing.
	"edge_segment_policies", "edge_delegations", "edge_issuances",
	// Format 17: the F4 AD CS certificate-database summary, same pairing.
	"adcs_ca_databases",
	// Format 18: I4's tenant-scoped diagnostic projection.
	"enrollment_diagnostic_observations", "enrollment_diagnostics",
	// Format 23: normalized AD CS template/ACL posture is now rebuilt from the
	// signed inventory observation event instead of an ephemeral SQL callback.
	"adcs_template_posture",
	// Format 21: parent before child keeps restore safe for the decision table's
	// composite foreign key into the immutable request.
	"operation_approval_requests", "operation_approval_decisions"}

// joinReadModel renders the read-model table list for a TRUNCATE, matching the set
// the rebuild path empties so a snapshot restore starts from the same clean slate.
func joinReadModel() string { return strings.Join(ReadModelTables, ", ") }

// ErrNoSnapshot is returned by LatestSnapshotOffset when no tenant has a snapshot
// yet, so the boot path knows to fall through to the existing checkpoint catch-up
// (or a full rebuild) rather than treating the absence as an error.
var ErrNoSnapshot = errors.New("store: no read-model snapshot")

// WriteTenantSnapshot captures one tenant's current read-model rows. It is the
// compatibility entry point for narrow callers; the periodic worker uses
// WriteReadModelSnapshots so every tenant row belongs to one complete generation.
// A direct write still stamps the exact current tenant set. In a multi-tenant
// deployment that deliberately makes the partial generation unrestorable until a
// complete capture replaces it; one tenant's new positive offset can never be
// mistaken for coverage of its missing neighbors.
//
// The shared privacy history-operation barrier is outermost, followed by the
// projection lock and only then PostgreSQL reads/writes. This is the global order
// used by catch-up, rebuild, restore, and privacy erasure. The barrier is
// re-entrant through its callback context, so a higher-level guarded caller does
// not consume another pool connection or deadlock itself.
func (s *Store) WriteTenantSnapshot(ctx context.Context, tenantID string, coveredSeq uint64) error {
	if tenantID == "" {
		return fmt.Errorf("store: WriteTenantSnapshot requires a tenant id (AN-1)")
	}
	return s.WithPrivacyReadModelReplacementBarrier(ctx, func(barrierCtx context.Context) error {
		return s.WithProjectionLock(barrierCtx, func(projectionCtx context.Context) error {
			checkpoint, err := s.ProjectionCheckpoint(projectionCtx)
			if err != nil {
				return fmt.Errorf("store: read checkpoint for direct snapshot: %w", err)
			}
			if coveredSeq != checkpoint {
				return fmt.Errorf(
					"store: direct snapshot offset %d differs from projection checkpoint %d",
					coveredSeq, checkpoint,
				)
			}
			tenants, err := s.ListTenants(projectionCtx)
			if err != nil {
				return fmt.Errorf("store: list tenants for direct snapshot: %w", err)
			}
			metadata, found := newSnapshotSetMetadata(coveredSeq, tenants, tenantID)
			if !found {
				return fmt.Errorf("store: direct snapshot tenant %s is not registered", tenantID)
			}
			return s.writeTenantSnapshotInSet(projectionCtx, tenantID, coveredSeq, metadata)
		})
	})
}

// WriteReadModelSnapshots captures the exact current tenant set at one projection
// head. The operation is intentionally crash-conservative: it first invalidates
// the current-format generation, then writes each tenant row separately. A crash
// can leave a partial set, but its stamped count/digest cannot validate, so restore
// falls back to event history. Zero tenants explicitly leaves no v22 snapshots.
func (s *Store) WriteReadModelSnapshots(ctx context.Context) (int, error) {
	var written int
	err := s.WithPrivacyReadModelReplacementBarrier(ctx, func(barrierCtx context.Context) error {
		return s.WithProjectionLock(barrierCtx, func(projectionCtx context.Context) error {
			coveredSeq, err := s.ProjectionCheckpoint(projectionCtx)
			if err != nil {
				return fmt.Errorf("store: read checkpoint for snapshot set: %w", err)
			}
			tenants, err := s.ListTenants(projectionCtx)
			if err != nil {
				return fmt.Errorf("store: list tenants for snapshot set: %w", err)
			}
			metadata, _ := newSnapshotSetMetadata(coveredSeq, tenants, "")
			// A complete generation is published by its repeated metadata, not by a
			// mutable pointer row. Removing the prior current-format rows first means a
			// crash exposes only an obviously incomplete generation.
			//trstctl:system-query — deployment-wide invalidation of the reconstructible current snapshot generation; every replacement row below is captured under its tenant's FORCE-RLS context (AN-1 exemption).
			if _, err := s.pool.Exec(projectionCtx,
				`DELETE FROM read_model_snapshots WHERE format_version = $1`,
				SnapshotFormatVersion); err != nil {
				return fmt.Errorf("store: invalidate prior snapshot set: %w", err)
			}
			if len(tenants) == 0 {
				return nil
			}
			for _, tenant := range tenants {
				if err := s.writeTenantSnapshotInSet(
					projectionCtx, tenant.TenantID, coveredSeq, metadata,
				); err != nil {
					return err
				}
				written++
			}
			complete, err := readCompleteSnapshotSet(projectionCtx, s.pool)
			if err != nil {
				return fmt.Errorf("store: verify completed snapshot set: %w", err)
			}
			if complete.metadata != metadata {
				return errors.New("store: completed snapshot set metadata changed during capture")
			}
			return nil
		})
	})
	return written, err
}

func newSnapshotSetMetadata(
	coveredSeq uint64,
	tenants []Tenant,
	requiredTenantID string,
) (snapshotSetMetadata, bool) {
	tenantIDs := make([]string, 0, len(tenants))
	found := requiredTenantID == ""
	for _, tenant := range tenants {
		tenantIDs = append(tenantIDs, tenant.TenantID)
		if tenant.TenantID == requiredTenantID {
			found = true
		}
	}
	sort.Strings(tenantIDs)
	basis := []byte("trstctl:read-model-snapshot-tenant-set:v1\x00" + strings.Join(tenantIDs, "\x00"))
	return snapshotSetMetadata{
		ID:              uuid.NewString(),
		CoveredSequence: coveredSeq,
		TenantCount:     len(tenantIDs),
		TenantSetSHA256: crypto.SHA256Hex(basis),
	}, found
}

func (s *Store) writeTenantSnapshotInSet(
	ctx context.Context,
	tenantID string,
	coveredSeq uint64,
	metadata snapshotSetMetadata,
) error {
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
  'certificate_profiles',  (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM certificate_profiles t),
  'acme_dns01_provider_configs', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM acme_dns01_provider_configs t),
  'mdm_scep_policies',     (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM mdm_scep_policies t),
  'identities',            (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM identities t),
  'certificates',          (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM certificates t),
  'crypto_assets',         (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM crypto_assets t),
  'pqc_migration_campaigns', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM pqc_migration_campaigns t),
  'pqc_migration_campaign_findings', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM pqc_migration_campaign_findings t),
  'agents',                (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM agents t),
  'ca_key_ceremonies',     (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM ca_key_ceremonies t),
  'ca_ceremony_approvals', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM ca_ceremony_approvals t),
  'ca_issued_certs',       (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM ca_issued_certs t),
  'ca_crls',               (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM ca_crls t),
  'ca_ocsp_responders',    (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM ca_ocsp_responders t),
  'discovery_sources',     (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM discovery_sources t),
  'discovery_schedules',   (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM discovery_schedules t),
  'discovery_runs',        (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM discovery_runs t),
  'discovery_findings',    (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM discovery_findings t),
  'discovery_coverage',    (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM discovery_coverage t),
  'notification_channels', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM notification_channels t),
  'notification_reads',     (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM notification_reads t),
  'notification_threshold_deliveries', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM notification_threshold_deliveries t),
  'notification_test_operations', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM notification_test_operations t),
  'notification_delivery_receipts', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM notification_delivery_receipts t),
  'connector_delivery_receipts', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM connector_delivery_receipts t),
  'lifecycle_rotation_runs', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM lifecycle_rotation_runs t),
  'incident_executions',   (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM incident_executions t),
  'incident_fleet_reissuance_runs', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM incident_fleet_reissuance_runs t),
  'remediation_playbook_runs', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM remediation_playbook_runs t),
  'pam_sessions',          (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM pam_sessions t),
  'compliance_report_schedules', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM compliance_report_schedules t),
  'secret_rotation_schedules', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM secret_rotation_schedules t),
  'dynamic_secret_operations', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM dynamic_secret_operations t),
  'dynamic_secret_leases', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM dynamic_secret_leases t),
  -- Secret-sync restore must reproduce the committed target order byte-for-byte.
  -- Array order is explicit too: jsonb aggregation has no implicit row order.
  'secret_sync_jobs',      (SELECT coalesce(jsonb_agg(to_jsonb(t.*) ORDER BY t.target, t.target_order, t.id), '[]'::jsonb) FROM secret_sync_jobs t),
  'managed_key_operations',(SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM managed_key_operations t),
  'managed_keys',          (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM managed_keys t),
  'code_signing_operations',(SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM code_signing_operations t),
  'privacy_subject_erasures', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM privacy_subject_erasures t),
  'privacy_retention_runs', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM privacy_retention_runs t),
  'privacy_archive_erasure_attestations', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM privacy_archive_erasure_attestations t),
  'nhi_access_review_campaigns', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM nhi_access_review_campaigns t),
  'nhi_access_review_items', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM nhi_access_review_items t),
  'access_change_requests', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM access_change_requests t),
  'access_change_request_decisions', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM access_change_request_decisions t),
  'machine_sessions',      (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM machine_sessions t),
  'machine_auth_method_overrides', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM machine_auth_method_overrides t),
  'identity_transitions',  (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM identity_transitions t)
) || jsonb_build_object(
  -- Lives in the SECOND object on purpose: the first is at Postgres's
  -- hard ceiling of 100 function arguments (50 tables), and a 51st entry
  -- there fails capture outright with SQLSTATE 54023 rather than
  -- degrading. Add new tables here.
  'acme_upstream_authorizations', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM acme_upstream_authorizations t),
  'endpoint_verifications', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM endpoint_verifications t),
  'workload_attester_trust_sources', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM workload_attester_trust_sources t),
  'secret_sync_workload_identity_sources', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM secret_sync_workload_identity_sources t),
  'tenant_key_domains', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM tenant_key_domains t),
  'tenant_members', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM tenant_members t),
  -- ORDER BY inside the aggregate: ca_authorities references itself
  -- (parent_id, replaces_id), both FKs point at strictly older rows, and the
  -- restore inserts each table as one statement in array order.
  'ca_authorities', (SELECT coalesce(jsonb_agg(to_jsonb(t.*) ORDER BY t.created_at, t.id), '[]'::jsonb) FROM ca_authorities t),
  'agent_cert_revocations', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM agent_cert_revocations t),
  'owner_ownership_conflicts', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM owner_ownership_conflicts t),
  'cmdb_reconcile_schedules', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM cmdb_reconcile_schedules t),
  'issuance_requests', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM issuance_requests t),
  'mdm_device_correlations', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM mdm_device_correlations t),
  'agent_upgrade_campaigns', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM agent_upgrade_campaigns t),
  'agent_upgrade_dispatches', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM agent_upgrade_dispatches t),
  'mdm_poll_schedules', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM mdm_poll_schedules t),
  'ticket_intake_schedules', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM ticket_intake_schedules t),
  'edge_segment_policies', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM edge_segment_policies t),
  'edge_delegations', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM edge_delegations t),
  'edge_issuances', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM edge_issuances t),
  'adcs_ca_databases', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM adcs_ca_databases t),
  'enrollment_diagnostic_observations', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM enrollment_diagnostic_observations t),
  'enrollment_diagnostics', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM enrollment_diagnostics t),
  'outbox_reconciliation_conflicts', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM outbox_reconciliation_conflicts t),
  'operation_approval_requests', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM operation_approval_requests t),
  'operation_approval_decisions', (SELECT coalesce(jsonb_agg(to_jsonb(t.*)), '[]'::jsonb) FROM operation_approval_decisions t)
) || jsonb_build_object(
  '_trstctl_snapshot_set', jsonb_build_object(
    'id', $1::text,
    'covered_seq', $2::bigint,
    'tenant_count', $3::integer,
    'tenant_set_sha256', $4::text
  )
)`
		var payload []byte
		if err := tx.QueryRow(ctx, payloadSQL,
			metadata.ID, int64(metadata.CoveredSequence), // #nosec G115 -- the projection sequence is stored in a PostgreSQL bigint throughout this file (CWE-190)
			metadata.TenantCount, metadata.TenantSetSHA256,
		).Scan(&payload); err != nil {
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
			tenantID, int64(coveredSeq), SnapshotFormatVersion, payload) // #nosec G115 -- event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190)
		if err != nil {
			return fmt.Errorf("store: write snapshot: %w", err)
		}
		return nil
	})
}

// LatestSnapshotOffset returns the one projection head covered by a complete v22
// snapshot generation. Completeness is proven from the rows themselves: every row
// must name the same capture ID/head/count/set digest, and recomputing the digest
// over the actual tenant IDs must match. Missing, mixed, legacy, or partial sets
// return ErrNoSnapshot, so a cold database replays sanitized history from its zero
// checkpoint instead of trusting a surviving neighbor's positive offset.
func (s *Store) LatestSnapshotOffset(ctx context.Context) (uint64, error) {
	set, err := readCompleteSnapshotSet(ctx, s.pool)
	if err != nil {
		return 0, err
	}
	return set.metadata.CoveredSequence, nil
}

func readCompleteSnapshotSet(
	ctx context.Context,
	querier snapshotSetQuerier,
) (completeSnapshotSet, error) {
	//trstctl:system-query — cross-tenant read of reconstructible snapshot metadata; tenant IDs are used only to prove the exact complete capture set before a system restore (AN-1 exemption).
	rows, err := querier.Query(ctx, `SELECT tenant_id::text, covered_seq,
		payload -> $2
		FROM read_model_snapshots
		WHERE format_version = $1
		ORDER BY tenant_id`, SnapshotFormatVersion, snapshotSetPayloadKey)
	if err != nil {
		return completeSnapshotSet{}, fmt.Errorf("store: read snapshot set metadata: %w", err)
	}
	defer rows.Close()

	var out completeSnapshotSet
	seen := make(map[string]struct{})
	for rows.Next() {
		var (
			tenantID   string
			coveredSeq int64
			raw        []byte
		)
		if err := rows.Scan(&tenantID, &coveredSeq, &raw); err != nil {
			return completeSnapshotSet{}, err
		}
		if coveredSeq < 0 || len(raw) == 0 {
			return completeSnapshotSet{}, ErrNoSnapshot
		}
		var metadata snapshotSetMetadata
		if err := json.Unmarshal(raw, &metadata); err != nil {
			return completeSnapshotSet{}, ErrNoSnapshot
		}
		parsedID, err := uuid.Parse(metadata.ID)
		if err != nil || parsedID.String() != metadata.ID || metadata.TenantCount <= 0 ||
			metadata.CoveredSequence != uint64(coveredSeq) ||
			len(metadata.TenantSetSHA256) != 64 {
			return completeSnapshotSet{}, ErrNoSnapshot
		}
		if _, duplicate := seen[tenantID]; duplicate {
			return completeSnapshotSet{}, ErrNoSnapshot
		}
		seen[tenantID] = struct{}{}
		if len(out.tenantIDs) == 0 {
			out.metadata = metadata
		} else if metadata != out.metadata {
			return completeSnapshotSet{}, ErrNoSnapshot
		}
		out.tenantIDs = append(out.tenantIDs, tenantID)
	}
	if err := rows.Err(); err != nil {
		return completeSnapshotSet{}, err
	}
	if len(out.tenantIDs) == 0 || len(out.tenantIDs) != out.metadata.TenantCount {
		return completeSnapshotSet{}, ErrNoSnapshot
	}
	// ORDER BY tenant_id already gives the canonical order. Sort defensively so a
	// future query refactor cannot weaken the digest proof by changing row order.
	sort.Strings(out.tenantIDs)
	basis := []byte("trstctl:read-model-snapshot-tenant-set:v1\x00" + strings.Join(out.tenantIDs, "\x00"))
	if crypto.SHA256Hex(basis) != out.metadata.TenantSetSHA256 {
		return completeSnapshotSet{}, ErrNoSnapshot
	}
	return out, nil
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
	// Validate completeness on the caller's exact restore transaction BEFORE the
	// destructive truncate. A target snapshot deleted by privacy preparation leaves
	// its neighbors stamped with the old larger tenant set, so this returns
	// ErrNoSnapshot and the caller replays sanitized history from its checkpoint.
	complete, err := readCompleteSnapshotSet(ctx, tx)
	if err != nil {
		return 0, err
	}
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
		`SELECT tenant_id, payload FROM read_model_snapshots
		 WHERE format_version = $1 AND payload -> $2 ->> 'id' = $3
		 ORDER BY tenant_id`,
		SnapshotFormatVersion, snapshotSetPayloadKey, complete.metadata.ID)
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
	if restored != complete.metadata.TenantCount {
		return 0, ErrNoSnapshot
	}
	return restored, nil
}

// deleteTenantSnapshotTx removes one tenant's disposable derived cache inside a
// caller-owned transaction and returns the exact physical row count (zero or one).
// Privacy preparation uses this primitive so cache deletion, its crash marker, and
// the non-PII count evidence commit or roll back together.
func deleteTenantSnapshotTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
) (int, error) {
	tag, err := tx.Exec(ctx,
		`DELETE FROM read_model_snapshots WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return 0, fmt.Errorf("store: delete tenant read-model snapshot: %w", err)
	}
	deleted := tag.RowsAffected()
	if deleted < 0 || deleted > 1 {
		return 0, fmt.Errorf("store: tenant snapshot deletion changed %d rows", deleted)
	}
	return int(deleted), nil
}

func (s *Store) tenantSnapshotCount(ctx context.Context, tenantID string) (int, error) {
	var count int
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM read_model_snapshots WHERE tenant_id = $1`,
			tenantID,
		).Scan(&count)
	})
	return count, err
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
