// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

// TestPAMDiscoveryActorPrivacyA267O2 is A267-O2: who saved a privileged
// account discovery source, requested a scan, dismissed an account (and the
// dismissal's reason) or imported one (and the import's reason) is a subject.
// A subject export lists those rows; an erasure rewrites the actors and clears
// the reasons in that tenant only, so the scan readback never shows the
// erased actor again; retention keeps a finished scan's requester as a digest.
func TestPAMDiscoveryActorPrivacyA267O2(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	const actor = "dana.ops@example.test"
	const runID = "a2670200-0000-4000-8000-000000000001"
	const accountID = "a2670200-0000-4000-8000-000000000002"
	const importedID = "a2670200-0000-4000-8000-000000000003"
	for _, tenant := range []string{tenantA, tenantB} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenant, Name: "Discovery actors"}); err != nil {
			t.Fatal(err)
		}
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			for _, statement := range []string{
				`INSERT INTO pam_discovery_sources (tenant_id, provider_id, provider_type, interval_seconds, saved_by, saved_at)
				 VALUES ($1, 'orders-pg', 'postgresql', 0, $2, now() - interval '500 days')`,
				`INSERT INTO pam_discovery_runs (tenant_id, id, provider_id, status, started_at, finished_at, requested_by)
				 VALUES ($1, '` + runID + `', 'orders-pg', 'completed', now() - interval '500 days', now() - interval '500 days', $2)`,
				`INSERT INTO pam_discovered_accounts (tenant_id, provider_id, account_key, id, name, kind, privileges, first_seen_run, first_seen_at,
				        last_seen_run, last_seen_at, status, dismissed_by, dismissed_reason)
				 VALUES ($1, 'orders-pg', 'role:etl', '` + accountID + `', 'etl', 'role', '[]'::jsonb, '` + runID + `', now(), '` + runID + `', now(),
				        'dismissed', $2, 'not managed here, per ' || $2)`,
				`INSERT INTO pam_imported_accounts (tenant_id, provider_id, account_key, discovered_account_id, name, kind, privileges, folder, reason,
				        import_request_id, approval_request_id, imported_by, imported_at)
				 VALUES ($1, 'orders-pg', 'role:app_admin', '` + importedID + `', 'app_admin', 'role', '[]'::jsonb, 'db-admins', 'requested by ' || $2,
				        gen_random_uuid(), gen_random_uuid(), $2, now())`,
			} {
				if _, err := tx.Exec(ctx, statement, tenant, actor); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	tables := []string{"pam_discovery_sources", "pam_discovery_runs", "pam_discovered_accounts", "pam_imported_accounts"}
	exported, err := s.SelectPrivacySubjectExport(ctx, tenantA, actor)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range tables {
		if exported.Counts[table] != 1 {
			t.Fatalf("the actor's %s row is missing from their subject export: %v", table, exported.Counts)
		}
	}
	erased, err := s.SelectPrivacySubjectErasure(ctx, tenantA, actor)
	if err != nil {
		t.Fatal(err)
	}
	erased.RequestedByRef = privacy.SubjectRef(tenantA, "privacy-operator")
	erased.Reason = "discovery actor erasure"
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.ApplyPrivacySubjectErasedTx(ctx, tx, erased) }); err != nil {
		t.Fatal(err)
	}
	actors := func(tenant string) []string {
		t.Helper()
		var savedBy, requestedBy, dismissedBy, dismissedReason, importedBy, importReason string
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT
				(SELECT saved_by FROM pam_discovery_sources WHERE tenant_id = $1 AND provider_id = 'orders-pg'),
				(SELECT requested_by FROM pam_discovery_runs WHERE tenant_id = $1 AND id = '`+runID+`'),
				(SELECT dismissed_by FROM pam_discovered_accounts WHERE tenant_id = $1 AND id = '`+accountID+`'),
				(SELECT dismissed_reason FROM pam_discovered_accounts WHERE tenant_id = $1 AND id = '`+accountID+`'),
				(SELECT imported_by FROM pam_imported_accounts WHERE tenant_id = $1 AND discovered_account_id = '`+importedID+`'),
				(SELECT reason FROM pam_imported_accounts WHERE tenant_id = $1 AND discovered_account_id = '`+importedID+`')`, tenant).
				Scan(&savedBy, &requestedBy, &dismissedBy, &dismissedReason, &importedBy, &importReason)
		}); err != nil {
			t.Fatal(err)
		}
		return []string{savedBy, requestedBy, dismissedBy, dismissedReason, importedBy, importReason}
	}
	// The actor fields name the placeholder; the reasons, free text that may
	// name the actor in any form, are cleared, as a PAM session's are.
	placeholder := privacy.Placeholder(privacy.SubjectRef(tenantA, actor))
	if got, want := actors(tenantA), []string{placeholder, placeholder, placeholder, "", placeholder, ""}; strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("after the erasure the erased tenant's discovery reads %q, want %q", got, want)
	}
	// The scan readback is the read model: the erased actor is not in it.
	runs, err := s.ListPAMDiscoveryRuns(ctx, tenantA, "orders-pg", 10)
	if err != nil || len(runs) != 1 || runs[0].RequestedBy != placeholder {
		t.Fatalf("the scan readback = %+v, %v", runs, err)
	}
	for i, got := range actors(tenantB) {
		if !strings.Contains(got, actor) {
			t.Fatalf("an erasure in another tenant changed field %d of this tenant's discovery to %q", i, got)
		}
	}
	run, err := s.SelectPrivacyRetention(ctx, tenantB, "a2670200-0000-4000-8000-0000000000ff", privacy.DefaultRetentionPolicy(), time.Now().UTC())
	if err != nil || run.Counts["pam_discovery_runs"] != 1 {
		t.Fatalf("a finished scan's requester is missing from retention: %v %v", run.Counts, err)
	}
	run.RequestedByRef = privacy.SubjectRef(tenantB, "privacy-operator")
	if err := s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error { return s.ApplyPrivacyRetentionEnforcedTx(ctx, tx, run) }); err != nil {
		t.Fatal(err)
	}
	if got := actors(tenantB)[1]; !strings.HasPrefix(got, "retained:") || strings.Contains(got, actor) {
		t.Fatalf("retention kept the scan's requester as %q, want a retained digest", got)
	}
}
