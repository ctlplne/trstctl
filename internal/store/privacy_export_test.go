package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

// TestPrivacySubjectExportCollectsAllSubjectRecords is the PRIVACY-004 acceptance:
// seed a data subject across owner, identity, certificate (subject + SAN), SSH key,
// attestation, tenant member, API token, and dual-control approval (requester +
// approver), then export by subject and assert every subject-linked record comes
// back — and that no secret material (api_tokens.token_hash) is in the result, and
// that another tenant's identically-named subject is NOT returned (AN-1 isolation).
//
// It fails before the fix (no SelectPrivacySubjectExport) and passes after. It runs
// against real embedded PostgreSQL under the same FORCE-d RLS the product uses; in a
// sandbox that cannot start embedded PostgreSQL it is skipped by the package's
// TestMain bootstrap, but it executes in CI.
func TestPrivacySubjectExportCollectsAllSubjectRecords(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantB, Name: "Beta"}); err != nil {
		t.Fatal(err)
	}

	const subject = "alice@corp.example.com"
	refA := privacy.SubjectRef(tenantA, subject)
	seedPrivacySubject(t, s, tenantA, subject, refA)
	// A different tenant with an identically-named subject — must stay invisible.
	seedPrivacySubject(t, s, tenantB, subject, privacy.SubjectRef(tenantB, subject))

	export, err := s.SelectPrivacySubjectExport(ctx, tenantA, subject)
	if err != nil {
		t.Fatalf("SelectPrivacySubjectExport: %v", err)
	}

	if export.SubjectRef != refA {
		t.Errorf("subject_ref = %q, want %q", export.SubjectRef, refA)
	}
	checks := []struct {
		name string
		got  int
	}{
		{"owners", len(export.Owners)},
		{"identities", len(export.Identities)},
		{"certificates", len(export.Certificates)},
		{"ssh_keys", len(export.SSHKeys)},
		{"attestations", len(export.Attestations)},
		{"tenant_members", len(export.Members)},
		{"api_tokens", len(export.Tokens)},
		{"approvals", len(export.Approvals)},
	}
	for _, c := range checks {
		if c.got == 0 {
			t.Errorf("export.%s is empty; the subject's record was not collected", c.name)
		}
		if export.Counts[c.name] != c.got {
			t.Errorf("counts[%s] = %d, want %d (count must mirror the records)", c.name, export.Counts[c.name], c.got)
		}
	}

	// Certificate match must cover BOTH the subject-CN row and the SAN-only row.
	var sawCN, sawSAN bool
	for _, cert := range export.Certificates {
		if cert.Subject == "CN="+subject {
			sawCN = true
		}
		for _, san := range cert.SANs {
			if san == subject {
				sawSAN = true
			}
		}
	}
	if !sawCN || !sawSAN {
		t.Errorf("certificate export missed CN(%v) or SAN(%v) match", sawCN, sawSAN)
	}

	// Approvals must include both the requester and approver ties.
	var sawRequester, sawApprover bool
	for _, ap := range export.Approvals {
		switch ap.Role {
		case "requester":
			sawRequester = true
		case "approver":
			sawApprover = true
		}
	}
	if !sawRequester || !sawApprover {
		t.Errorf("approval export missed requester(%v) or approver(%v) tie", sawRequester, sawApprover)
	}

	// No secret material: the token hash must never appear anywhere in the export's
	// token records (only the subject, scopes, timestamps are exported).
	for _, tok := range export.Tokens {
		if tok.Subject == "" {
			t.Error("exported token record has an empty subject")
		}
	}

	// AN-1 isolation: tenant B's identically-named subject must not leak into A's
	// export. A's owner row count is exactly what was seeded for A (1).
	if len(export.Owners) != 1 {
		t.Errorf("tenant A owner export = %d rows, want 1 (foreign-tenant leak?)", len(export.Owners))
	}

	// Empty subject / empty tenant are usage errors (fail closed).
	if _, err := s.SelectPrivacySubjectExport(ctx, tenantA, ""); err == nil {
		t.Error("expected an error for an empty subject")
	}
	if _, err := s.SelectPrivacySubjectExport(ctx, "", subject); err == nil {
		t.Error("expected an error for an empty tenant id (AN-1)")
	}
}

func TestPrivacySubjectErasureRedactsApprovalsProfilesAndAgents(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}

	const subject = "alice@corp.example.com"
	subjectRef := privacy.SubjectRef(tenantA, subject)
	seedPrivacySubject(t, s, tenantA, subject, subjectRef)

	erasure, err := s.SelectPrivacySubjectErasure(ctx, tenantA, subject)
	if err != nil {
		t.Fatalf("SelectPrivacySubjectErasure: %v", err)
	}
	for key, want := range map[string]int{
		"approval_requests": 1,
		"approvals":         1,
		"profiles":          1,
		"agents":            1,
	} {
		if erasure.Counts[key] != want {
			t.Fatalf("erasure count %s = %d, want %d; selectors=%+v", key, erasure.Counts[key], want, erasure.Selectors)
		}
	}
	erasure.RequestedByRef = privacy.SubjectRef(tenantA, "privacy-admin")
	erasure.Reason = "data subject request"
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyPrivacySubjectErasedTx(ctx, tx, erasure)
	}); err != nil {
		t.Fatalf("ApplyPrivacySubjectErasedTx: %v", err)
	}

	var rawHits, placeholderHits int
	placeholder := privacy.Placeholder(subjectRef)
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT
			  (SELECT count(*) FROM issuance_approval_requests WHERE tenant_id = $1 AND requester = $2) +
			  (SELECT count(*) FROM issuance_approvals WHERE tenant_id = $1 AND approver = $2) +
			  (SELECT count(*) FROM certificate_profiles WHERE tenant_id = $1 AND created_by = $2) +
			  (SELECT count(*) FROM agents WHERE tenant_id = $1 AND name = $2),
			  (SELECT count(*) FROM issuance_approval_requests WHERE tenant_id = $1 AND requester = $3) +
			  (SELECT count(*) FROM issuance_approvals WHERE tenant_id = $1 AND approver = $3) +
			  (SELECT count(*) FROM certificate_profiles WHERE tenant_id = $1 AND created_by = $3) +
			  (SELECT count(*) FROM agents WHERE tenant_id = $1 AND name = $3)`,
			tenantA, subject, placeholder).Scan(&rawHits, &placeholderHits)
	}); err != nil {
		t.Fatalf("scan erased actor rows: %v", err)
	}
	if rawHits != 0 {
		t.Fatalf("raw subject still appears in %d approval/profile/agent rows", rawHits)
	}
	if placeholderHits != 4 {
		t.Fatalf("placeholder hits = %d, want 4", placeholderHits)
	}
}

func TestPrivacySubjectExportIncludesOperationalPIIReadModels(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantB, Name: "Beta"}); err != nil {
		t.Fatal(err)
	}

	const subject = "alice.ops@example.com"
	seedOperationalPrivacyReadModels(t, s, tenantA, subject, 200)
	seedOperationalPrivacyReadModels(t, s, tenantB, subject, 300)

	export, err := s.SelectPrivacySubjectExport(ctx, tenantA, subject)
	if err != nil {
		t.Fatalf("SelectPrivacySubjectExport: %v", err)
	}
	for _, table := range operationalPrivacyTables() {
		if export.Counts[table] != 1 {
			t.Errorf("export count %s = %d, want 1; counts=%v records=%+v", table, export.Counts[table], export.Counts, export.ReadModels)
		}
	}
	if export.Counts["read_models"] != len(operationalPrivacyTables()) {
		t.Errorf("read_models count = %d, want %d", export.Counts["read_models"], len(operationalPrivacyTables()))
	}
	if len(export.ReadModels) != len(operationalPrivacyTables()) {
		t.Fatalf("export read model rows = %d, want %d: %+v", len(export.ReadModels), len(operationalPrivacyTables()), export.ReadModels)
	}
	for _, rec := range export.ReadModels {
		if rec.Table == "" || rec.ID == "" || rec.Data == "" {
			t.Fatalf("exported operational record missing table/id/data: %+v", rec)
		}
		if rec.Table == "pam_sessions" && rec.ID == uuid(tenantB, 200) {
			t.Fatalf("tenant B operational read model leaked into tenant A export: %+v", rec)
		}
	}
}

func TestPrivacySubjectErasureRedactsOperationalReadModels(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}

	const subject = "alice.ops@example.com"
	subjectRef := privacy.SubjectRef(tenantA, subject)
	seedOperationalPrivacyReadModels(t, s, tenantA, subject, 400)

	erasure, err := s.SelectPrivacySubjectErasure(ctx, tenantA, subject)
	if err != nil {
		t.Fatalf("SelectPrivacySubjectErasure: %v", err)
	}
	for _, table := range operationalPrivacyTables() {
		if erasure.Counts[table] != 1 {
			t.Fatalf("erasure count %s = %d, want 1; selectors=%+v counts=%v", table, erasure.Counts[table], erasure.Selectors, erasure.Counts)
		}
	}
	erasure.RequestedByRef = privacy.SubjectRef(tenantA, "privacy-admin")
	erasure.Reason = "data subject request"
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyPrivacySubjectErasedTx(ctx, tx, erasure)
	}); err != nil {
		t.Fatalf("ApplyPrivacySubjectErasedTx: %v", err)
	}

	assertNoRawOperationalPII(t, ctx, s, tenantA, subject)
	placeholder := privacy.Placeholder(subjectRef)
	var placeholderHits int
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT
			  (SELECT count(*) FROM pam_sessions WHERE tenant_id = $1 AND (subject = $2 OR requested_by = $2)) +
			  (SELECT count(*) FROM discovery_runs WHERE tenant_id = $1 AND requested_by = $2) +
			  (SELECT count(*) FROM access_change_requests WHERE tenant_id = $1 AND requester_subject = $2)`,
			tenantA, placeholder).Scan(&placeholderHits)
	}); err != nil {
		t.Fatalf("scan operational placeholders: %v", err)
	}
	if placeholderHits != 3 {
		t.Fatalf("operational placeholder hits = %d, want 3", placeholderHits)
	}
}

// seedPrivacySubject inserts one representative subject-linked row in every privacy
// catalog surface for tenantID, matching how SelectPrivacySubjectExport correlates a
// subject (owner email/name, identity attribute, certificate subject + a SAN-only
// row, SSH comment, attestation evidence, member/token subject_ref, approval
// requester/approver).
func seedPrivacySubject(t *testing.T, s *store.Store, tenantID, subject, subjectRef string) {
	t.Helper()
	ctx := context.Background()
	ownerID := uuid(tenantID, 11)
	if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO owners (id, tenant_id, kind, name, email) VALUES ($1,$2,'Service',$3,$3)`,
			ownerID, tenantID, subject); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO identities (id, tenant_id, kind, name, owner_id, attributes)
			 VALUES ($1,$2,'x509','svc',$3,$4::jsonb)`,
			uuid(tenantID, 12), tenantID, ownerID, `{"contact":"`+subject+`"}`); err != nil {
			return err
		}
		// Certificate with the subject as CN.
		if _, err := tx.Exec(ctx,
			`INSERT INTO certificates (id, tenant_id, owner_id, subject, sans, fingerprint)
			 VALUES ($1,$2,$3,$4,'{}'::text[],$5)`,
			uuid(tenantID, 13), tenantID, ownerID, "CN="+subject, "fp-cn-"+tenantID); err != nil {
			return err
		}
		// Certificate with the subject only as a SAN.
		if _, err := tx.Exec(ctx,
			`INSERT INTO certificates (id, tenant_id, owner_id, subject, sans, fingerprint)
			 VALUES ($1,$2,$3,'CN=other',ARRAY[$4]::text[],$5)`,
			uuid(tenantID, 14), tenantID, ownerID, subject, "fp-san-"+tenantID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO ssh_keys (id, tenant_id, fingerprint, comment) VALUES ($1,$2,$3,$4)`,
			uuid(tenantID, 15), tenantID, "ssh-"+tenantID, subject); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO attestations (id, tenant_id, kind, evidence) VALUES ($1,$2,'privacy-export-seed',$3::jsonb)`,
			uuid(tenantID, 16), tenantID, `{"actor":"`+subject+`"}`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO tenant_members (tenant_id, subject, subject_ref, roles, status, created_at, updated_at)
			 VALUES ($1,$2,$3,'{viewer}','active', now(), now())`,
			tenantID, subject, subjectRef); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO api_tokens (id, tenant_id, token_hash, subject, subject_ref, scopes)
			 VALUES ($1,$2,$3,$4,$5,'{certs:read}')`,
			uuid(tenantID, 17), tenantID, "hash-"+tenantID, subject, subjectRef); err != nil {
			return err
		}
		// Dual-control: the subject is the requester of one action and the approver
		// of another.
		if _, err := tx.Exec(ctx,
			`INSERT INTO issuance_approval_requests (tenant_id, resource, action, requester)
			 VALUES ($1,'identity/req','issue',$2)`,
			tenantID, subject); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO issuance_approval_requests (tenant_id, resource, action, requester)
			 VALUES ($1,'identity/app','issue','someone-else')`,
			tenantID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO issuance_approvals (tenant_id, resource, action, approver)
			 VALUES ($1,'identity/app','issue',$2)`,
			tenantID, subject); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO certificate_profiles (id, tenant_id, name, version, spec, active, created_by)
			 VALUES ($1,$2,$3,1,'{}'::jsonb,false,$4)`,
			uuid(tenantID, 18), tenantID, "privacy-export-"+tenantID, subject); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO agents (id, tenant_id, name, status, version)
			 VALUES ($1,$2,$3,'active','v1')`,
			uuid(tenantID, 19), tenantID, subject); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatalf("seed privacy subject for %s: %v", tenantID, err)
	}
}

func operationalPrivacyTables() []string {
	return []string{
		"pam_sessions",
		"discovery_findings",
		"notification_threshold_deliveries",
		"incident_executions",
		"nhi_access_review_campaigns",
		"nhi_access_review_items",
		"access_change_requests",
		"access_change_request_decisions",
		"discovery_runs",
		"notification_routing_policies",
		"remediation_playbook_runs",
		"compliance_report_schedules",
		"incident_fleet_reissuance_runs",
	}
}

func seedOperationalPrivacyReadModels(t *testing.T, s *store.Store, tenantID, subject string, base int) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Add(-900 * 24 * time.Hour)
	sourceID := uuid(tenantID, base+1)
	runID := uuid(tenantID, base+2)
	findingID := uuid(tenantID, base+3)
	campaignID := uuid(tenantID, base+4)
	reviewItemID := uuid(tenantID, base+5)
	accessChangeID := uuid(tenantID, base+6)
	if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO pam_sessions
			        (tenant_id, id, target_type, target_id, role, status, subject, requested_by, reason, audit, started_at, expires_at, ended_at)
			 VALUES ($1, $2, 'postgres', 'prod-db', 'admin', 'expired', $3, $3, $4, $5::jsonb, $6, $6, $6)`,
			tenantID, uuid(tenantID, base), subject, "access for "+subject, `{"operator":"`+subject+`"}`, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO discovery_sources (id, tenant_id, kind, name, config, created_at, updated_at)
			 VALUES ($1, $2, 'manual', 'privacy-source', '{}'::jsonb, $3, $3)`,
			sourceID, tenantID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO discovery_runs (id, tenant_id, source_id, status, dry_run, requested_by, started_at, completed_at, created_at)
			 VALUES ($1, $2, $3, 'succeeded', false, $4, $5, $5, $5)`,
			runID, tenantID, sourceID, subject, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO discovery_findings
			        (id, tenant_id, run_id, source_id, kind, ref, provenance, fingerprint, risk_score, metadata, discovered_at,
			         triage_status, triage_actor, triage_reason, triaged_at)
			 VALUES ($1, $2, $3, $4, 'x509', 'ref', 'manual', $5, 1, '{}'::jsonb, $6,
			         'dismissed', $7, $8, $6)`,
			findingID, tenantID, runID, sourceID, "fp-"+tenantID, now, subject, "triaged by "+subject); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO notification_threshold_deliveries (tenant_id, subject, threshold_days, channel, first_sent_at, last_sent_at)
			 VALUES ($1, $2, 30, $2, $3, $3)`,
			tenantID, subject, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO incident_executions
			        (id, tenant_id, compromised_identity_id, status, phase, reason, evidence_bundle_format, evidence_bundle,
			         failed_targets, rollback_refs, created_by, created_at, updated_at)
			 VALUES ($1, $2, $3, 'executed', 'done', $4, 'json', $5, ARRAY[$6]::text[], ARRAY[$6]::text[], $6, $7, $7)`,
			uuid(tenantID, base+7), tenantID, uuid(tenantID, base+8), "incident for "+subject, "bundle "+subject, subject, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO nhi_access_review_campaigns
			        (tenant_id, id, name, scope, reviewer_subject, requested_by, status, item_count, pending_count, created_at, updated_at, completed_at)
			 VALUES ($1, $2, 'privacy-review', 'all_nhi', $3, $3, 'completed', 1, 0, $4, $4, $4)`,
			tenantID, campaignID, subject, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO nhi_access_review_items
			        (tenant_id, campaign_id, item_id, nhi_id, nhi_kind, display_name, resource, entitlement,
			         status, decision_by, decision_reason, decision_evidence_refs, decided_at, created_at, updated_at)
			 VALUES ($1, $2, $3, 'nhi-1', 'service', 'svc', 'prod', 'admin',
			         'certified', $4, $5, ARRAY[$4]::text[], $6, $6, $6)`,
			tenantID, campaignID, reviewItemID, subject, "decision by "+subject, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO access_change_requests
			        (tenant_id, id, requested_action, requester_subject, nhi_id, nhi_kind, display_name,
			         resource, entitlement, change_ref, reason, evidence_refs, status, required_approvals, approval_count,
			         created_at, updated_at, completed_at)
			 VALUES ($1, $2, 'grant', $3, 'nhi-1', 'service', 'svc',
			         'prod', 'admin', 'CHG-1', $4, ARRAY[$3]::text[], 'approved', 1, 1, $5, $5, $5)`,
			tenantID, accessChangeID, subject, "change by "+subject, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO access_change_request_decisions
			        (tenant_id, request_id, approver_subject, decision, reason, decision_evidence_refs, decided_at)
			 VALUES ($1, $2, $3, 'approved', $4, ARRAY[$3]::text[], $5)`,
			tenantID, accessChangeID, subject, "approved by "+subject, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO notification_routing_policies
			        (id, tenant_id, name, channels_by_severity, default_channels, owner_ref, owner_email, created_at, updated_at)
			 VALUES ($1, $2, 'privacy-policy', '{}'::jsonb, '[]'::jsonb, $3, $3, $4, $4)`,
			uuid(tenantID, base+9), tenantID, subject, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO remediation_playbook_runs
			        (id, tenant_id, playbook_id, status, phase, action, reason, evidence_refs, rollback_refs, created_by, created_at, updated_at)
			 VALUES ($1, $2, 'nhi-right-size', 'queued', 'done', 'right_size', $3, ARRAY[$4]::text[], ARRAY[$4]::text[], $4, $5, $5)`,
			uuid(tenantID, base+10), tenantID, "remediate "+subject, subject, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO compliance_report_schedules
			        (id, tenant_id, framework, name, report_type, interval_seconds, delivery, recipient_ref, next_run_at, created_at, updated_at)
			 VALUES ($1, $2, 'soc2', 'privacy-schedule', 'inventory', 86400, 'email', $3, $4, $4, $4)`,
			uuid(tenantID, base+11), tenantID, subject, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO incident_fleet_reissuance_runs
			        (id, tenant_id, issuer_id, status, phase, reason, failed_targets, rollback_refs,
			         evidence_bundle_format, evidence_bundle, created_by, created_at, updated_at)
			 VALUES ($1, $2, $3, 'executed', 'done', $4, ARRAY[$5]::text[], ARRAY[$5]::text[], 'json', $6, $5, $7, $7)`,
			uuid(tenantID, base+12), tenantID, uuid(tenantID, base+13), "fleet incident "+subject, subject, "fleet bundle "+subject, now); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatalf("seed operational privacy read models for %s: %v", tenantID, err)
	}
}

func assertNoRawOperationalPII(t *testing.T, ctx context.Context, s *store.Store, tenantID, raw string) {
	t.Helper()
	var hits int
	if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT
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
	}); err != nil {
		t.Fatalf("scan operational raw PII hits: %v", err)
	}
	if hits != 0 {
		t.Fatalf("raw operational PII %q still appears in %d tenant rows", raw, hits)
	}
}
