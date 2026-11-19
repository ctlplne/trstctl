// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestPrivacySubjectExportOmitsRetainedDiscoveryProviderText(t *testing.T) {
	st := newStore(t)
	ctx := t.Context()
	if err := st.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Fixture tenant"}); err != nil {
		t.Fatal(err)
	}
	const (
		subject   = "fixture-privacy-requester"
		sourceID  = "70500000-0000-4000-8000-000000000002"
		runID     = "70500000-0000-4000-8000-000000000003"
		findingID = "70500000-0000-4000-8000-000000000004"
		scalarID  = "70500000-0000-4000-8000-000000000005"
		marker    = "fixtureopaqueretailederror"
	)
	seed := func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO discovery_sources (tenant_id, id, kind, name, created_at, updated_at)
			VALUES ($1, $2, 'manual', 'fixture-source', now(), now())`, tenantA, sourceID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO discovery_runs (tenant_id, id, source_id, status, requested_by, error, created_at)
			VALUES ($1, $2, $3, 'failed', $4, $5, now())`, tenantA, runID, sourceID, subject, marker); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO discovery_findings
			(tenant_id, id, source_id, run_id, kind, ref, provenance, triage_actor, metadata, discovered_at)
			VALUES ($1, $2, $3, $4, 'nhi-attack-path', 'fixture-ref', 'manual', $5,
			jsonb_build_object('reason', $6::text, 'status', 'unknown'), now())`,
			tenantA, findingID, sourceID, runID, subject, "the provider could not be read: "+marker); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO discovery_findings
			(tenant_id, id, source_id, run_id, kind, ref, provenance, triage_actor, metadata, discovered_at)
			VALUES ($1, $2, $3, $4, 'nhi-attack-path', 'fixture-scalar', 'manual', $5, '"fixture-scalar-metadata"'::jsonb, now())`,
			tenantA, scalarID, sourceID, runID, subject)
		return err
	}
	if err := st.WithTenant(ctx, tenantA, seed); err != nil {
		t.Fatal(err)
	}
	export, err := st.SelectPrivacySubjectExport(ctx, tenantA, subject)
	if err != nil {
		t.Fatal(err)
	}
	if export.Counts["discovery_findings"] != 2 || export.Counts["discovery_runs"] != 1 {
		t.Fatal("the subject export must include the historical finding and run records")
	}
	for _, row := range export.ReadModels {
		if strings.Contains(row.Data, marker) {
			t.Errorf("the retained %s export contained provider-supplied text", row.Table)
		}
		if row.ID == scalarID && !strings.Contains(row.Data, "fixture-scalar-metadata") {
			t.Error("the retained scalar finding metadata was lost")
		}
	}
}
