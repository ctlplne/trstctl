package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// PRIVACY-003 acceptance: non-audit PII retention is defined, event-sourced,
// served, and enforced by the assembled background worker without deleting the
// security/audit evidence needed to verify retention happened.
func TestServedPrivacyRetentionWorkerPseudonymizesStalePII(t *testing.T) {
	if testing.Short() {
		t.Skip("starts an embedded PostgreSQL; skipped in -short")
	}
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	const rawSubject = "alice.retention@example.com"

	st := newServerTestStore(t)
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if err := seedStalePIIRows(t, ctx, st, tenantID, rawSubject); err != nil {
		t.Fatalf("seed stale rows: %v", err)
	}
	adminToken := seedServedAPIToken(t, ctx, st, tenantID, "privacy-retention-admin", []string{
		string(authz.PrivacyRead), string(authz.PrivacyWrite), string(authz.AuditRead),
	})

	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	auditKey, err := jose.GenerateRSASigningKey("privacy-003-audit")
	if err != nil {
		_ = log.Close()
		t.Fatalf("generate audit key: %v", err)
	}
	srv, err := Build(ctx, Deps{
		Store: st, Log: log, AuditSigningKey: auditKey,
		PrivacyRetentionEnabled: true,
		PrivacyRetentionPolicy:  privacy.DefaultRetentionPolicy(),
	})
	if err != nil {
		_ = log.Close()
		t.Fatalf("build server: %v", err)
	}
	defer func() { _ = srv.Shutdown(context.Background()) }()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	sum, err := srv.RunPrivacyRetentionOnce(ctx)
	if err != nil {
		t.Fatalf("RunPrivacyRetentionOnce: %v", err)
	}
	if sum.TenantsProcessed != 1 || sum.RowsAnonymized == 0 {
		t.Fatalf("retention summary = %+v, want one tenant and anonymized rows", sum)
	}
	for _, key := range []string{
		"owners", "identities", "certificates", "ssh_keys", "attestations", "approval_requests", "approvals", "profiles", "api_tokens", "tenant_members", "agents",
		"pam_sessions", "discovery_findings", "notification_threshold_deliveries", "incident_executions", "nhi_access_review_campaigns", "nhi_access_review_items",
		"access_change_requests", "access_change_request_decisions", "discovery_runs", "notification_routing_policies", "remediation_playbook_runs",
		"compliance_report_schedules", "incident_fleet_reissuance_runs",
	} {
		if sum.Counts[key] != 1 {
			t.Fatalf("retention count %s = %d, want 1; summary=%+v", key, sum.Counts[key], sum)
		}
	}
	assertNoRawRetentionPII(t, ctx, st, tenantID, rawSubject)

	code, body := doBearer(t, ts, http.MethodGet, "/api/v1/privacy/retention-runs", adminToken, "", nil)
	if code != http.StatusOK {
		t.Fatalf("list retention runs = %d, want 200; body=%s", code, body)
	}
	if bytes.Contains(body, []byte(rawSubject)) || !bytes.Contains(body, []byte(`"owners":1`)) {
		t.Fatalf("retention run response leaked raw PII or missed counts: %s", body)
	}

	const routeSubject = "bob.retention@example.com"
	if err := seedStaleSSHKey(t, ctx, st, tenantID, routeSubject); err != nil {
		t.Fatalf("seed route ssh key: %v", err)
	}
	code, body = doBearer(t, ts, http.MethodPost, "/api/v1/privacy/retention-runs", adminToken, "privacy-retention-manual", nil)
	if code != http.StatusCreated {
		t.Fatalf("manual retention run = %d, want 201; body=%s", code, body)
	}
	if bytes.Contains(body, []byte(routeSubject)) || !bytes.Contains(body, []byte(`"ssh_keys":1`)) {
		t.Fatalf("manual retention response leaked raw PII or missed ssh count: %s", body)
	}
	assertNoRawRetentionPII(t, ctx, st, tenantID, routeSubject)

	var sawRetentionEvent bool
	if err := log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.Type != projections.EventPrivacyRetentionEnforced || ev.TenantID != tenantID {
			return nil
		}
		sawRetentionEvent = true
		if bytes.Contains(ev.Data, []byte(rawSubject)) || bytes.Contains(ev.Data, []byte(routeSubject)) {
			t.Fatalf("privacy retention event leaked raw PII: %s", ev.Data)
		}
		if !bytes.Contains(ev.Data, []byte(`"cutoffs"`)) || !bytes.Contains(ev.Data, []byte(`"counts"`)) {
			t.Fatalf("privacy retention event missing cutoffs/counts: %s", ev.Data)
		}
		return nil
	}); err != nil {
		t.Fatalf("replay event log: %v", err)
	}
	if !sawRetentionEvent {
		t.Fatal("privacy.retention.enforced event was not recorded")
	}

	code, body = doBearer(t, ts, http.MethodGet, "/api/v1/audit/export", adminToken, "", nil)
	if code != http.StatusOK {
		t.Fatalf("audit export = %d body=%s", code, body)
	}
	var exportResp struct {
		Bundle string `json:"bundle"`
	}
	if err := json.Unmarshal(body, &exportResp); err != nil || exportResp.Bundle == "" {
		t.Fatalf("decode export response: %v body=%s", err, body)
	}
	bundle, err := audit.VerifyBundle(exportResp.Bundle, auditKey.JWKS())
	if err != nil {
		t.Fatalf("verify export bundle: %v", err)
	}
	bundleJSON, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal verified bundle: %v", err)
	}
	if bytes.Contains(bundleJSON, []byte(rawSubject)) || !bytes.Contains(bundleJSON, []byte(projections.EventPrivacyRetentionEnforced)) {
		t.Fatalf("verified export bundle leaked raw PII or missed retention event: %s", bundleJSON)
	}
}

func seedStalePIIRows(t *testing.T, ctx context.Context, st *store.Store, tenantID, raw string) error {
	t.Helper()
	old := time.Now().UTC().Add(-900 * 24 * time.Hour)
	subjectRef := privacy.SubjectRef(tenantID, raw)
	return st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		activeOwner := "22222222-2222-2222-2222-222222222222"
		if _, err := tx.Exec(ctx,
			`INSERT INTO owners (id, tenant_id, kind, name, email, created_at)
			 VALUES ($1, $2, 'workload', 'active-owner', 'owner-active@example.com', $3)`,
			activeOwner, tenantID, old); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO owners (id, tenant_id, kind, name, email, created_at)
			 VALUES ('33333333-3333-3333-3333-333333333333', $1, 'user', $2, $2, $3)`,
			tenantID, raw, old); err != nil {
			return err
		}
		identityID := "44444444-4444-4444-4444-444444444444"
		if _, err := tx.Exec(ctx,
			`INSERT INTO identities (id, tenant_id, kind, name, owner_id, status, not_after, attributes, created_at)
			 VALUES ($1, $2, 'x509_certificate', $3, $4, 'revoked', $5, $6::jsonb, $5)`,
			identityID, tenantID, raw, activeOwner, old, `{"contact":"`+raw+`"}`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO certificates
			        (id, tenant_id, owner_id, subject, sans, issuer, serial, fingerprint, key_algorithm,
			         not_after, deployment_location, source, created_at, status, revoked_at)
			 VALUES ('55555555-5555-5555-5555-555555555555', $1, $2, $3, $4, 'ca', '01',
			         'fp-retention-alice', 'rsa', $5, $3, $3, $5, 'revoked', $5)`,
			tenantID, activeOwner, raw, []string{raw}, old); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO ssh_keys (id, tenant_id, fingerprint, comment, location, orphaned, created_at)
			 VALUES ('66666666-6666-6666-6666-666666666666', $1, 'ssh-retention-alice', $2, $2, true, $3)`,
			tenantID, raw, old); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO attestations (id, tenant_id, identity_id, kind, evidence, created_at)
			 VALUES ('77777777-7777-7777-7777-777777777777', $1, $2, 'manual', $3::jsonb, $4)`,
			tenantID, identityID, `{"reviewer":"`+raw+`"}`, old); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO issuance_approval_requests (tenant_id, resource, action, requester, created_at)
			 VALUES ($1, $2, 'issue', $3, $4)`,
			tenantID, identityID, raw, old); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO issuance_approvals (tenant_id, resource, action, approver, approved_at)
			 VALUES ($1, $2, 'issue', $3, $4)`,
			tenantID, identityID, raw, old); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO certificate_profiles (id, tenant_id, name, version, spec, active, created_by, created_at)
			 VALUES ('88888888-8888-8888-8888-888888888888', $1, 'retention-profile', 1, '{}'::jsonb, false, $2, $3)`,
			tenantID, raw, old); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO api_tokens
			        (id, tenant_id, token_hash, subject, subject_ref, scopes, expires_at, created_at, revoked_at)
			 VALUES ('99999999-9999-9999-9999-999999999999', $1, 'retention-token-hash-alice', $2, $3, '{}', $4, $4, $4)`,
			tenantID, raw, subjectRef, old); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO tenant_members
			        (tenant_id, subject, subject_ref, display_name, email, roles, source, status,
			         created_at, updated_at, offboarded_at)
			 VALUES ($1, $2, $3, $2, $2, '{}', 'manual', 'offboarded', $4, $4, $4)`,
			tenantID, raw, subjectRef, old); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO agents (id, tenant_id, name, status, version, last_seen_at, created_at)
				 VALUES ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', $1, $2, 'stale', 'v1', $3, $3)`,
			tenantID, raw, old); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO pam_sessions
				        (tenant_id, id, target_type, target_id, role, status, subject, requested_by, reason, audit, started_at, expires_at, ended_at)
				 VALUES ($1, 'abababab-0000-0000-0000-000000000001', 'postgres', 'prod-db', 'admin', 'expired', $2, $2, $3, $4::jsonb, $5, $5, $5)`,
			tenantID, raw, "access for "+raw, `{"operator":"`+raw+`"}`, old); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO discovery_sources (id, tenant_id, kind, name, config, created_at, updated_at)
				 VALUES ('abababab-0000-0000-0000-000000000002', $1, 'manual', 'privacy-retention-source', '{}'::jsonb, $2, $2)`,
			tenantID, old); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO discovery_runs (id, tenant_id, source_id, status, dry_run, requested_by, started_at, completed_at, created_at)
				 VALUES ('abababab-0000-0000-0000-000000000003', $1, 'abababab-0000-0000-0000-000000000002', 'succeeded', false, $2, $3, $3, $3)`,
			tenantID, raw, old); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO discovery_findings
				        (id, tenant_id, run_id, source_id, kind, ref, provenance, fingerprint, risk_score, metadata, discovered_at,
				         triage_status, triage_actor, triage_reason, triaged_at)
				 VALUES ('abababab-0000-0000-0000-000000000004', $1, 'abababab-0000-0000-0000-000000000003',
				         'abababab-0000-0000-0000-000000000002', 'x509', 'ref', 'manual', 'fp-retention-discovery', 1, '{}'::jsonb, $2,
				         'dismissed', $3, $4, $2)`,
			tenantID, old, raw, "triaged by "+raw); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO notification_threshold_deliveries (tenant_id, subject, threshold_days, channel, first_sent_at, last_sent_at)
				 VALUES ($1, $2, 30, $2, $3, $3)`,
			tenantID, raw, old); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO incident_executions
				        (id, tenant_id, compromised_identity_id, status, phase, reason, evidence_bundle_format, evidence_bundle,
				         failed_targets, rollback_refs, created_by, created_at, updated_at)
				 VALUES ('abababab-0000-0000-0000-000000000005', $1, $2, 'executed', 'done', $3, 'json', $4,
				         ARRAY[$5]::text[], ARRAY[$5]::text[], $5, $6, $6)`,
			tenantID, identityID, "incident for "+raw, "bundle "+raw, raw, old); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO nhi_access_review_campaigns
				        (tenant_id, id, name, scope, reviewer_subject, requested_by, status, item_count, pending_count, created_at, updated_at, completed_at)
				 VALUES ($1, 'abababab-0000-0000-0000-000000000006', 'privacy-retention-review', 'all_nhi', $2, $2, 'completed', 1, 0, $3, $3, $3)`,
			tenantID, raw, old); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO nhi_access_review_items
				        (tenant_id, campaign_id, item_id, nhi_id, nhi_kind, display_name, resource, entitlement,
				         status, decision_by, decision_reason, decision_evidence_refs, decided_at, created_at, updated_at)
				 VALUES ($1, 'abababab-0000-0000-0000-000000000006', 'abababab-0000-0000-0000-000000000007', 'nhi-1', 'service', 'svc', 'prod', 'admin',
				         'certified', $2, $3, ARRAY[$2]::text[], $4, $4, $4)`,
			tenantID, raw, "decision by "+raw, old); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO access_change_requests
				        (tenant_id, id, requested_action, requester_subject, nhi_id, nhi_kind, display_name,
				         resource, entitlement, change_ref, reason, evidence_refs, status, required_approvals, approval_count,
				         created_at, updated_at, completed_at)
				 VALUES ($1, 'abababab-0000-0000-0000-000000000008', 'grant', $2, 'nhi-1', 'service', 'svc',
				         'prod', 'admin', 'CHG-RETENTION', $3, ARRAY[$2]::text[], 'approved', 1, 1, $4, $4, $4)`,
			tenantID, raw, "change by "+raw, old); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO access_change_request_decisions
				        (tenant_id, request_id, approver_subject, decision, reason, decision_evidence_refs, decided_at)
				 VALUES ($1, 'abababab-0000-0000-0000-000000000008', $2, 'approved', $3, ARRAY[$2]::text[], $4)`,
			tenantID, raw, "approved by "+raw, old); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO notification_routing_policies
				        (id, tenant_id, name, channels_by_severity, default_channels, owner_ref, owner_email, created_at, updated_at)
				 VALUES ('abababab-0000-0000-0000-000000000009', $1, 'privacy-retention-policy', '{}'::jsonb, '[]'::jsonb, $2, $2, $3, $3)`,
			tenantID, raw, old); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO remediation_playbook_runs
				        (id, tenant_id, playbook_id, status, phase, action, reason, evidence_refs, rollback_refs, created_by, created_at, updated_at)
				 VALUES ('abababab-0000-0000-0000-000000000010', $1, 'nhi-right-size', 'queued', 'done', 'right_size', $2, ARRAY[$3]::text[], ARRAY[$3]::text[], $3, $4, $4)`,
			tenantID, "remediate "+raw, raw, old); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO compliance_report_schedules
				        (id, tenant_id, framework, name, report_type, interval_seconds, delivery, recipient_ref, next_run_at, created_at, updated_at)
				 VALUES ('abababab-0000-0000-0000-000000000011', $1, 'soc2', 'privacy-retention-schedule', 'inventory', 86400, 'email', $2, $3, $3, $3)`,
			tenantID, raw, old); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO incident_fleet_reissuance_runs
				        (id, tenant_id, issuer_id, status, phase, reason, failed_targets, rollback_refs,
				         evidence_bundle_format, evidence_bundle, created_by, created_at, updated_at)
				 VALUES ('abababab-0000-0000-0000-000000000012', $1, 'abababab-0000-0000-0000-000000000013', 'executed', 'done',
				         $2, ARRAY[$3]::text[], ARRAY[$3]::text[], 'json', $4, $3, $5, $5)`,
			tenantID, "fleet incident "+raw, raw, "fleet bundle "+raw, old); err != nil {
			return err
		}
		return nil
	})
}

func seedStaleSSHKey(t *testing.T, ctx context.Context, st *store.Store, tenantID, raw string) error {
	t.Helper()
	old := time.Now().UTC().Add(-900 * 24 * time.Hour)
	return st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO ssh_keys (id, tenant_id, fingerprint, comment, location, orphaned, created_at)
			 VALUES ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', $1, 'ssh-retention-bob', $2, $2, true, $3)`,
			tenantID, raw, old)
		return err
	})
}

func assertNoRawRetentionPII(t *testing.T, ctx context.Context, st *store.Store, tenantID, raw string) {
	t.Helper()
	var hits int
	err := st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT
			  (SELECT count(*) FROM owners WHERE tenant_id = $1 AND (name = $2 OR email = $2)) +
			  (SELECT count(*) FROM identities WHERE tenant_id = $1 AND (name = $2 OR position($2 in attributes::text) > 0)) +
			  (SELECT count(*) FROM certificates WHERE tenant_id = $1 AND (subject = $2 OR $2 = ANY(sans) OR deployment_location = $2 OR source = $2)) +
			  (SELECT count(*) FROM ssh_keys WHERE tenant_id = $1 AND (comment = $2 OR location = $2)) +
			  (SELECT count(*) FROM attestations WHERE tenant_id = $1 AND position($2 in evidence::text) > 0) +
			  (SELECT count(*) FROM issuance_approval_requests WHERE tenant_id = $1 AND requester = $2) +
			  (SELECT count(*) FROM issuance_approvals WHERE tenant_id = $1 AND approver = $2) +
				  (SELECT count(*) FROM certificate_profiles WHERE tenant_id = $1 AND created_by = $2) +
				  (SELECT count(*) FROM api_tokens WHERE tenant_id = $1 AND subject = $2) +
				  (SELECT count(*) FROM tenant_members WHERE tenant_id = $1 AND (subject = $2 OR display_name = $2 OR email = $2)) +
				  (SELECT count(*) FROM agents WHERE tenant_id = $1 AND name = $2) +
				  (SELECT count(*) FROM pam_sessions WHERE tenant_id = $1 AND (subject = $2 OR requested_by = $2 OR position($2 in reason) > 0 OR position($2 in audit::text) > 0)) +
				  (SELECT count(*) FROM discovery_findings WHERE tenant_id = $1 AND (triage_actor = $2 OR position($2 in triage_reason) > 0)) +
				  (SELECT count(*) FROM notification_threshold_deliveries WHERE tenant_id = $1 AND (subject = $2 OR channel = $2)) +
				  (SELECT count(*) FROM incident_executions WHERE tenant_id = $1 AND (created_by = $2 OR position($2 in reason) > 0 OR position($2 in evidence_bundle) > 0 OR $2 = ANY(failed_targets) OR $2 = ANY(rollback_refs))) +
				  (SELECT count(*) FROM nhi_access_review_campaigns WHERE tenant_id = $1 AND (reviewer_subject = $2 OR requested_by = $2)) +
				  (SELECT count(*) FROM nhi_access_review_items WHERE tenant_id = $1 AND (decision_by = $2 OR position($2 in decision_reason) > 0 OR $2 = ANY(decision_evidence_refs))) +
				  (SELECT count(*) FROM access_change_requests WHERE tenant_id = $1 AND (requester_subject = $2 OR position($2 in reason) > 0 OR $2 = ANY(evidence_refs))) +
				  (SELECT count(*) FROM access_change_request_decisions WHERE tenant_id = $1 AND (approver_subject = $2 OR position($2 in reason) > 0 OR $2 = ANY(decision_evidence_refs))) +
				  (SELECT count(*) FROM discovery_runs WHERE tenant_id = $1 AND requested_by = $2) +
				  (SELECT count(*) FROM notification_routing_policies WHERE tenant_id = $1 AND (owner_ref = $2 OR owner_email = $2)) +
				  (SELECT count(*) FROM remediation_playbook_runs WHERE tenant_id = $1 AND (created_by = $2 OR position($2 in reason) > 0 OR $2 = ANY(evidence_refs) OR $2 = ANY(rollback_refs))) +
				  (SELECT count(*) FROM compliance_report_schedules WHERE tenant_id = $1 AND recipient_ref = $2) +
				  (SELECT count(*) FROM incident_fleet_reissuance_runs WHERE tenant_id = $1 AND (created_by = $2 OR position($2 in reason) > 0 OR position($2 in evidence_bundle) > 0 OR $2 = ANY(failed_targets) OR $2 = ANY(rollback_refs)))`,
			tenantID, raw).Scan(&hits)
	})
	if err != nil {
		t.Fatalf("scan raw PII hits: %v", err)
	}
	if hits != 0 {
		t.Fatalf("raw PII %q still appears in %d tenant rows", raw, hits)
	}

	codepoints := []string{"retained:", "erased:"}
	var found bool
	err = st.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var sample string
		if err := tx.QueryRow(ctx,
			`SELECT coalesce(
			      (SELECT name FROM owners WHERE tenant_id = $1 AND name LIKE 'retained:%' LIMIT 1),
			      (SELECT subject FROM tenant_members WHERE tenant_id = $1 AND subject LIKE 'erased:%' LIMIT 1),
			      ''
			  )`,
			tenantID).Scan(&sample); err != nil {
			return err
		}
		for _, prefix := range codepoints {
			if strings.HasPrefix(sample, prefix) {
				found = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan pseudonymized sample: %v", err)
	}
	if !found {
		t.Fatalf("no retained/erased placeholder found after retention")
	}
}
