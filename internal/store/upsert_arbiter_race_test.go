// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// Every projection that upserts into a table with a second unique index is
// applied by the request-side projector and by the durable event tail, so two
// identical applies of one event race on the row. INSERT ... ON CONFLICT is
// race-safe only on its arbiter index: when both applies pass the arbiter
// pre-check together, both insert speculatively and the loser trips the other
// unique index with a raw unique_violation (DP2-043, DP2-046). Each site below
// is the guard for one such table: many simultaneous identical applies from a
// start barrier reproduce that window, every apply must converge, and exactly
// one row may exist afterwards. UPSERT_RACE_ROUNDS / UPSERT_RACE_PROJECTORS
// raise the pressure for a reproduction run.
type raceSite struct {
	name       string
	projection bool   // apply inside WithTenantProjection instead of WithTenant
	count      string // SQL counting the converged rows; $1 is the round key
	setup      func(t *testing.T, st *store.Store, round int) (tenant, key string, apply func(ctx context.Context, tx pgx.Tx) error)
}

func raceUUID(site, n int) string {
	return fmt.Sprintf("5a5a%04x-0000-4000-8000-%012x", site, n)
}

func raceEnvInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return def
}

func raceTenant(t *testing.T, st *store.Store, site, round int) string {
	t.Helper()
	tid := raceUUID(site, 900+round)
	if err := st.UpsertTenant(context.Background(), store.Tenant{TenantID: tid, Name: "race-tenant-" + strconv.Itoa(round), EventSeq: 40}); err != nil {
		t.Fatalf("register round tenant: %v", err)
	}
	return tid
}

const racePEM = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUAA==\n-----END CERTIFICATE-----\n"

func TestDualUniqueUpsertsConvergeUnderSimultaneousReplay(t *testing.T) {
	st := newStore(t)
	seedTwoTenants(t, st)
	seedRotationTickRegistration(t, st, tenantA)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)
	now := time.Now().UTC().Truncate(time.Microsecond)
	rounds := raceEnvInt("UPSERT_RACE_ROUNDS", 6)
	projectors := raceEnvInt("UPSERT_RACE_PROJECTORS", 12)

	sites := []raceSite{
		{name: "api_tokens", count: `SELECT count(*) FROM api_tokens WHERE id = $1::uuid`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				id := raceUUID(1, r)
				rec := store.APITokenRecord{ID: id, TenantID: tenantA, TokenHash: "hash-" + id, Subject: "svc", Scopes: []string{"read"}, CreatedAt: now}
				return tenantA, id, func(ctx context.Context, tx pgx.Tx) error { return st.ApplyAPITokenCreatedTx(ctx, tx, rec) }
			}},
		{name: "audit_feed_destinations", count: `SELECT count(*) FROM audit_feed_destinations WHERE id = $1::uuid`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				id := raceUUID(2, r)
				feed := store.AuditFeed{ID: id, TenantID: tenantA, Name: "siem-" + strconv.Itoa(r), Provider: "splunk-hec",
					EndpointURL: "https://collector.example.test/services/collector", TokenRef: "env:TOKEN",
					IntervalSeconds: 60, BatchSize: 100, Enabled: true, ConfigEventSequence: 1, NextRunAt: now, UpdatedAt: now}
				return tenantA, id, func(ctx context.Context, tx pgx.Tx) error { return st.ApplyAuditFeedConfiguredTx(ctx, tx, feed) }
			}},
		{name: "audit_feed_deliveries", count: `SELECT count(*) FROM audit_feed_deliveries WHERE batch_id = $1::uuid`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				feedID := raceUUID(3, 1000+r)
				feed := store.AuditFeed{ID: feedID, TenantID: tenantA, Name: "siem-batch-" + strconv.Itoa(r), Provider: "splunk-hec",
					EndpointURL: "https://collector.example.test/services/collector", TokenRef: "env:TOKEN",
					IntervalSeconds: 60, BatchSize: 100, Enabled: true, ConfigEventSequence: 1, NextRunAt: now, UpdatedAt: now}
				mustTx(t, ctx, st, func(tx pgx.Tx) error { return st.ApplyAuditFeedConfiguredTx(ctx, tx, feed) })
				id := raceUUID(3, r)
				batch := store.AuditFeedBatch{BatchID: id, TenantID: tenantA, DestinationID: feedID, Provider: "splunk-hec",
					StartSequence: uint64(r*10 + 1), EndSequence: uint64(r*10 + 9), RecordCount: 9, ChainHead: "deadbeef", // #nosec G115 -- small fixture counters (CWE-190)
					OutboxIdempotencyKey: "audit-feed:" + id, QueuedAt: now, Status: "queued"}
				return tenantA, id, func(ctx context.Context, tx pgx.Tx) error { return st.ApplyAuditFeedBatchQueuedTx(ctx, tx, batch, 60) }
			}},
		{name: "ca_ceremony_approvals", count: `SELECT count(*) FROM ca_ceremony_approvals WHERE ceremony_id = $1::uuid`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				ceremonyID, err := st.CreateKeyCeremony(ctx, tenantA, "root-rotation", "opener", 2)
				if err != nil {
					t.Fatalf("open ceremony: %v", err)
				}
				eventID := "evt-" + raceUUID(4, r)
				seq := uint64(r + 1) // #nosec G115 -- small fixture counter (CWE-190)
				return tenantA, ceremonyID, func(ctx context.Context, tx pgx.Tx) error {
					return st.ApplyKeyCeremonyApprovedTx(ctx, tx, tenantA, ceremonyID, "custodian-1", eventID, seq, now)
				}
			}},
		{name: "ca_authorities", count: `SELECT count(*) FROM ca_authorities WHERE id = $1::uuid`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				id := raceUUID(5, r)
				a := store.CAAuthority{ID: id, TenantID: tenantA, CommonName: "Race CA " + id[:8], Kind: "root", Status: "active",
					CertificatePEM: racePEM, SignerHandle: "signer-" + id, Serial: "01" + strconv.Itoa(r), MaxPathLen: -1, CreatedAt: now}
				return tenantA, id, func(ctx context.Context, tx pgx.Tx) error { return st.ApplyCAAuthorityCreatedTx(ctx, tx, a, "", now) }
			}},
		{name: "compliance_report_schedules", count: `SELECT count(*) FROM compliance_report_schedules WHERE id = $1::uuid`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				id := raceUUID(6, r)
				s := store.ComplianceReportSchedule{ID: id, TenantID: tenantA, Framework: "soc2", Name: "sched-" + strconv.Itoa(r), ReportType: "audit_summary",
					IntervalSeconds: 3600, Enabled: true, Delivery: "audit_export", NextRunAt: now, CreatedAt: now, UpdatedAt: now}
				return tenantA, id, func(ctx context.Context, tx pgx.Tx) error {
					return st.ApplyComplianceReportScheduleUpsertedTx(ctx, tx, s)
				}
			}},
		{name: "crypto_assets", count: `SELECT count(*) FROM crypto_assets WHERE id = $1::uuid`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				id := raceUUID(7, r)
				a := store.CryptoAsset{ID: id, TenantID: tenantA, Kind: "host-config", Location: "/etc/race/" + id, Protocol: "TLSv1",
					Strength: "weak", QuantumVulnerable: true, OutOfPolicy: true}
				return tenantA, id, func(ctx context.Context, tx pgx.Tx) error { return st.ApplyCryptoAssetObservedTx(ctx, tx, a, 10, now) }
			}},
		{name: "ct_watched_domains", count: `SELECT count(*) FROM ct_watched_domains WHERE domain = $1`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				id := raceUUID(8, r)
				domain := "r" + strconv.Itoa(r) + ".race.example.test"
				src := store.DiscoverySource{ID: id, TenantID: tenantA, Kind: "ct_log", Name: "ct-" + strconv.Itoa(r),
					Config: []byte(`{"log":"https://ct.example.test/2026","watched_domains":["` + domain + `"]}`), CreatedAt: now, UpdatedAt: now}
				return tenantA, domain, func(ctx context.Context, tx pgx.Tx) error { return st.ApplyDiscoverySourceUpsertedTx(ctx, tx, src) }
			}},
		{name: "tenant_epoch_ensure", count: `SELECT count(*) FROM application_secret_tenant_epochs WHERE tenant_id = $1::uuid`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				tid := raceTenant(t, st, 9, r)
				return tid, tid, func(ctx context.Context, _ pgx.Tx) error { _, err := st.DynamicSecretTenantEpoch(ctx, tid); return err }
			}},
		{name: "tenant_epoch_pending", projection: true, count: `SELECT count(*) FROM application_secret_tenant_epochs WHERE tenant_id = $1::uuid`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				tid := raceTenant(t, st, 10, r)
				return tid, tid, func(ctx context.Context, tx pgx.Tx) error {
					_, err := st.ResolveDynamicSecretPendingTenantEpochTx(ctx, tx, tid, "", 41)
					return err
				}
			}},
		{name: "tenant_epoch_sync_random", projection: true, count: `SELECT count(*) FROM application_secret_tenant_epochs WHERE tenant_id = $1::uuid`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				tid := raceTenant(t, st, 11, r)
				return tid, tid, func(ctx context.Context, tx pgx.Tx) error {
					_, err := st.ResolveSecretSyncQueuedTenantEpochTx(ctx, tx, tid, "", 41)
					return err
				}
			}},
		{name: "tenant_epoch_sync_event", projection: true, count: `SELECT count(*) FROM application_secret_tenant_epochs WHERE tenant_id = $1::uuid`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				tid := raceTenant(t, st, 12, r)
				epoch := raceUUID(12, 5000+r)
				return tid, tid, func(ctx context.Context, tx pgx.Tx) error {
					_, err := st.ResolveSecretSyncQueuedTenantEpochTx(ctx, tx, tid, epoch, 41)
					return err
				}
			}},
		{name: "dynamic_secret_leases", count: `SELECT count(*) FROM dynamic_secret_leases WHERE id = $1`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				epoch, err := st.DynamicSecretTenantEpoch(ctx, tenantA)
				if err != nil {
					t.Fatalf("tenant epoch: %v", err)
				}
				id := "lease-" + raceUUID(13, r)
				lease := store.DynamicSecretLease{ID: id, TenantID: tenantA, TenantEpoch: epoch, IdempotencyKey: "key-" + id,
					RequestBinding: "sha256:" + id, Provider: "postgresql", Role: "reader", IssueOutboxID: int64(8000 + r),
					IssuedAt: now, ExpiresAt: now.Add(time.Hour), HardExpiresAt: now.Add(2 * time.Hour), UpdatedAt: now}
				return tenantA, id, func(ctx context.Context, tx pgx.Tx) error { return st.ApplyDynamicSecretLeasePendingTx(ctx, tx, lease) }
			}},
		{name: "edge_delegations", count: `SELECT count(*) FROM edge_delegations WHERE id = $1::uuid`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				id := raceUUID(14, r)
				d := store.EdgeDelegation{TenantID: tenantA, ID: id, SegmentID: raceUUID(14, 500+r), CAID: raceUUID(14, 600+r),
					Host: "edge-" + strconv.Itoa(r), CommonName: "edge-" + strconv.Itoa(r), Serial: "serial-" + id, CertificatePEM: racePEM,
					PermittedDNSDomains: []string{}, ExcludedDNSDomains: []string{},
					AttestedKeySHA256: strings.Repeat("a", 64), AttestationCertSHA256: strings.Repeat("b", 64),
					Status: "active", NotBefore: now, NotAfter: now.Add(24 * time.Hour), CreatedAt: now, UpdatedAt: now}
				return tenantA, id, func(ctx context.Context, tx pgx.Tx) error { return st.ApplyEdgeDelegationIssuedTx(ctx, tx, d, 5) }
			}},
		{name: "mdm_device_correlations", count: `SELECT count(*) FROM mdm_device_correlations WHERE mdm_device_id = $1`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				dev := "device-" + raceUUID(15, r)
				observed := now
				c := store.MDMDeviceCorrelation{TenantID: tenantA, MDM: "intune", MDMDeviceID: dev, TransactionID: "tx-" + dev,
					InstallState: "ok", ObservedAt: &observed}
				return tenantA, dev, func(ctx context.Context, tx pgx.Tx) error { return st.ApplyMDMDeviceCorrelatedTx(ctx, tx, c) }
			}},
		{name: "operation_approval_requests", count: `SELECT count(*) FROM operation_approval_requests WHERE id = $1::uuid`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				id := raceUUID(16, r)
				req := raceApprovalRequest(id, now)
				return tenantA, id, func(ctx context.Context, tx pgx.Tx) error { return st.ApplyOperationApprovalRequestedTx(ctx, tx, req) }
			}},
		{name: "operation_approval_decisions", count: `SELECT count(*) FROM operation_approval_decisions WHERE request_id = $1::uuid`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				id := raceUUID(17, r)
				req := raceApprovalRequest(id, now)
				mustTx(t, ctx, st, func(tx pgx.Tx) error { return st.ApplyOperationApprovalRequestedTx(ctx, tx, req) })
				d := store.OperationApprovalDecision{TenantID: tenantA, RequestID: id, IntentDigest: req.IntentDigest, Approver: "security-approver",
					Decision: store.ApprovalDecisionApprove, EventID: raceUUID(17, 700+r), DecidedAt: now.Add(time.Minute)}
				return tenantA, id, func(ctx context.Context, tx pgx.Tx) error { return st.ApplyOperationApprovalDecisionTx(ctx, tx, d) }
			}},
		{name: "outbox_reconciliation_conflicts", count: `SELECT count(*) FROM outbox_reconciliation_conflicts WHERE source_event_id = $1`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				id := raceUUID(18, r)
				c := store.OutboxReconciliationConflict{ID: "conflict-" + id, TenantID: tenantA, SourceEventID: "evt-" + id,
					SourceEventSequence: uint64(r + 1), SourceEventType: "identity.deployed", IdempotencyKey: "key-" + id, // #nosec G115 -- small fixture counter (CWE-190)
					ExistingOutboxID: 1, ExistingDestination: "agent", ExistingEffectLane: "connector.bind", ExistingPayloadSHA256: strings.Repeat("a", 64),
					CandidateDestination: "agent", CandidateEffectLane: "connector.bind", CandidatePayloadSHA256: strings.Repeat("b", 64),
					Reason: "payload drift", Status: "quarantined", DetectedAt: now}
				return tenantA, "evt-" + id, func(ctx context.Context, tx pgx.Tx) error {
					return st.ApplyOutboxReconciliationConflictRecordedTx(ctx, tx, c)
				}
			}},
		{name: "agent_upgrade_campaigns", count: `SELECT count(*) FROM agent_upgrade_campaigns WHERE id = $1::uuid`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				tid := raceTenant(t, st, 19, r)
				id := raceUUID(19, r)
				return tid, id, func(ctx context.Context, tx pgx.Tx) error {
					return st.ApplyAgentUpgradeCampaignOpenedTx(ctx, tx, tid, id, "1.2.3", "ops", []byte(`{}`), now)
				}
			}},
		{name: "cmdb_reconcile_schedules", count: `SELECT count(*) FROM cmdb_reconcile_schedules WHERE tenant_id = $1::uuid`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				tid := raceTenant(t, st, 20, r)
				in := store.CMDBReconcileSchedule{InstanceURL: "https://now.example.test", TokenRef: "env:TRSTCTL_SERVICENOW_TOKEN", IntervalSeconds: 3600, Enabled: true} // #nosec G101 -- an env reference name in a fixture, not a credential (CWE-798)
				return tid, tid, func(ctx context.Context, tx pgx.Tx) error { return st.ApplyCMDBScheduleConfiguredTx(ctx, tx, tid, in) }
			}},
		{name: "owner_ownership_conflicts", count: `SELECT count(*) FROM owner_ownership_conflicts WHERE source_event_id = $1`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				id := raceUUID(21, r)
				ownerID := raceUUID(21, 400+r)
				conflicts := []store.OwnershipConflict{{OwnerID: ownerID, Field: "application_id", CurrentValue: "APP-1", CurrentSource: "human",
					IncomingValue: "APP-2", IncomingSource: "cmdb", IncomingRef: "ci:1", CurrentAttested: true}}
				return tenantA, "evt-" + id, func(ctx context.Context, tx pgx.Tx) error {
					return st.ApplyOwnershipReconciledTx(ctx, tx, tenantA, "evt-"+id, ownerID, nil, "cmdb", "ci:1", now, conflicts)
				}
			}},
		{name: "certificate_profiles", count: `SELECT count(*) FROM certificate_profiles WHERE id = $1::uuid`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				id := raceUUID(22, r)
				p := store.ProfileRecord{ID: id, TenantID: tenantA, Name: "profile-" + strconv.Itoa(r), Version: 1, Spec: json.RawMessage(`{}`), Active: true, CreatedBy: "ops", CreatedAt: now}
				return tenantA, id, func(ctx context.Context, tx pgx.Tx) error { return st.ApplyProfileVersionTx(ctx, tx, p) }
			}},
		{name: "remediation_playbook_runs", count: `SELECT count(*) FROM remediation_playbook_runs WHERE id = $1::uuid`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				id := raceUUID(23, r)
				run := store.RemediationPlaybookRun{ID: id, TenantID: tenantA, PlaybookID: "right-size", Status: "queued", Phase: "plan", Action: "right_size",
					IdempotencyKey: "key-" + id, RequestBinding: "sha256:" + id, InitialHTTPStatus: 202, InitialResponse: json.RawMessage(`{}`),
					ScopeDelta: json.RawMessage(`{}`), CreatedBy: "ops", CreatedAt: now, UpdatedAt: now}
				return tenantA, id, func(ctx context.Context, tx pgx.Tx) error {
					return st.ApplyRemediationPlaybookRunRecordedTx(ctx, tx, run)
				}
			}},
		{name: "secret_rotation_schedules", projection: true, count: `SELECT count(*) FROM secret_rotation_schedules WHERE id = $1::uuid`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				id := raceUUID(24, r)
				s := store.SecretRotationSchedule{ID: id, TenantID: tenantA, Name: "rotation-" + strconv.Itoa(r), Provider: "connector:ci", Key: "service/" + strconv.Itoa(r),
					OldRef: "version:1", IntervalSeconds: 3600, ConfigEventSequence: 1, Enabled: true, NextRunAt: now, CreatedAt: now, UpdatedAt: now}
				return tenantA, id, func(ctx context.Context, tx pgx.Tx) error {
					return st.ApplySecretRotationScheduleUpsertedTx(ctx, tx, s)
				}
			}},
		{name: "secret_sync_jobs", count: `SELECT count(*) FROM secret_sync_jobs WHERE id = $1`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				epoch, err := st.DynamicSecretTenantEpoch(ctx, tenantA)
				if err != nil {
					t.Fatalf("tenant epoch: %v", err)
				}
				id := "job-" + raceUUID(25, r)
				job := store.SecretSyncJob{ID: id, TenantID: tenantA, TenantEpoch: epoch, SecretName: "db-password", SecretVersion: 1, Target: "aws-secretsmanager",
					RemoteKey: "prod/db/" + strconv.Itoa(r), ValueDigest: "sha256:" + id, Status: "pending", OutboxID: int64(9000 + r), TargetOrder: int64(r + 1),
					IdempotencyKey: "key-" + id, RequestBinding: "sha256:" + id, RequestedAt: now, UpdatedAt: now}
				return tenantA, id, func(ctx context.Context, tx pgx.Tx) error { return st.ApplySecretSyncJobQueuedTx(ctx, tx, job) }
			}},
		{name: "secret_sync_workload_identity_sources", count: `SELECT count(*) FROM secret_sync_workload_identity_sources WHERE id = $1::uuid`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				trust := store.WorkloadAttesterTrustSource{ID: raceUUID(26, 800+r), TenantID: tenantA, Name: "trust-" + strconv.Itoa(r), Method: "oidc",
					Issuer: "https://issuer.example.test", Audience: "trstctl", JWKS: json.RawMessage(`{"keys":[]}`), Enabled: true, RotationVersion: 1, CreatedAt: now, UpdatedAt: now}
				mustTx(t, ctx, st, func(tx pgx.Tx) error { return st.ApplyWorkloadAttesterTrustSourceUpsertedTx(ctx, tx, trust) })
				id := raceUUID(26, r)
				src := store.SecretSyncWorkloadIdentitySource{ID: id, TenantID: tenantA, Name: "wi-" + strconv.Itoa(r), Provider: "aws",
					RoleARN: "arn:aws:iam::123456789012:role/trstctl-sync", Audience: "sts.amazonaws.com", Subject: "spiffe://race/" + strconv.Itoa(r),
					TargetID: "target-" + strconv.Itoa(r), AllowedRemoteKeyPrefixes: []string{}, WorkloadProofRef: "file:/var/run/proof.jwt",
					TrustSourceID: trust.ID, Enabled: true, CreatedAt: now, UpdatedAt: now}
				return tenantA, id, func(ctx context.Context, tx pgx.Tx) error {
					return st.ApplySecretSyncWorkloadIdentitySourceUpsertedTx(ctx, tx, src)
				}
			}},
		{name: "ssh_keys", count: `SELECT count(*) FROM ssh_keys WHERE id = $1::uuid`,
			setup: func(t *testing.T, st *store.Store, r int) (string, string, func(context.Context, pgx.Tx) error) {
				id := raceUUID(27, r)
				k := store.SSHKey{ID: id, TenantID: tenantA, Fingerprint: "SHA256:" + id, KeyType: "ssh-ed25519", Source: "ssh", Location: "host.race.example.test:22", CreatedAt: now}
				return tenantA, id, func(ctx context.Context, tx pgx.Tx) error { return st.ApplySSHKeyDiscoveredTx(ctx, tx, k) }
			}},
	}

	for _, site := range sites {
		site := site
		t.Run(site.name, func(t *testing.T) {
			for round := 0; round < rounds; round++ {
				tenant, key, apply := site.setup(t, st, round)
				start := make(chan struct{})
				errs := make(chan error, projectors)
				var wg sync.WaitGroup
				for i := 0; i < projectors; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						run := st.WithTenant
						if site.projection {
							run = st.WithTenantProjection
						}
						errs <- run(ctx, tenant, func(tx pgx.Tx) error { return apply(ctx, tx) })
					}()
				}
				close(start)
				wg.Wait()
				close(errs)
				for err := range errs {
					if err != nil {
						t.Fatalf("round %d: simultaneous identical applies must converge, got: %v", round, err)
					}
				}
				var count int
				if err := st.SystemPool().QueryRow(ctx, site.count, key).Scan(&count); err != nil {
					t.Fatalf("round %d: count rows: %v", round, err)
				}
				if count != 1 {
					t.Fatalf("round %d: rows for %s = %d, want exactly one", round, key, count)
				}
			}
		})
	}
}

func raceApprovalRequest(id string, now time.Time) store.OperationApprovalRequest {
	return store.OperationApprovalRequest{ID: id, TenantID: tenantA, IntentDigest: "sha256:" + strings.Repeat("a", 64),
		ResourceKind: "code_signing", ResourceID: "resource-" + id, ResourceName: "release-key", Action: "sign", Requester: "release-bot",
		EvidenceRefs: []string{}, RequiredApprovals: 1, CreatedAt: now, ExpiresAt: now.Add(time.Hour), UpdatedAt: now}
}
