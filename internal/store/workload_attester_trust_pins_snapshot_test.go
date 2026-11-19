// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// CR-384: the typed snapshot restore can load old source rows that lack ID
// columns and can restore new ID values under the correct tenant.
func TestSnapshotRestoresLegacyAndPinnedGitHubTrust(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	seedTwoTenants(t, s)
	for _, tenant := range []string{tenantA, tenantB} {
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			return s.ApplyWorkloadAttesterTrustSourceUpsertedTx(ctx, tx, store.WorkloadAttesterTrustSource{
				TenantID: tenant, ID: uuid(tenant, 38401), Name: "workflow", Method: "github_oidc",
				Audience: "trstctl", Enabled: true, AllowedOwners: []string{"acme"},
			})
		}); err != nil {
			t.Fatal(err)
		}
	}
	if count, err := s.WriteReadModelSnapshots(ctx); err != nil || count != 2 {
		t.Fatalf("snapshot capture = %d, error %v, want both tenants", count, err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE read_model_snapshots SET payload=jsonb_set(payload,
			'{workload_attester_trust_sources,0}',
			(payload #> '{workload_attester_trust_sources,0}') - 'allowed_owner_ids' - 'allowed_repository_ids')
			WHERE tenant_id=$1`, tenantA)
		return err
	}); err != nil {
		t.Fatalf("shape a pre-pin snapshot row: %v", err)
	}
	if err := s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE read_model_snapshots SET payload=jsonb_set(payload,
			'{workload_attester_trust_sources,0}', (payload #> '{workload_attester_trust_sources,0}') ||
			jsonb_build_object('allowed_owner_ids', $2::text[], 'allowed_repository_ids', $3::text[]))
			WHERE tenant_id=$1`, tenantB, []string{"9007199254740993"}, []string{"456"})
		return err
	}); err != nil {
		t.Fatalf("shape a pinned snapshot row: %v", err)
	}
	if err := s.RestoreReadModelTx(ctx, func(tx pgx.Tx) error {
		_, err := s.RestoreSnapshotsTx(ctx, tx)
		return err
	}); err != nil {
		t.Fatalf("restore both snapshot rows: %v", err)
	}
	for _, tenant := range []string{tenantA, tenantB} {
		var ownerIDs, repositoryIDs []string
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT allowed_owner_ids, allowed_repository_ids
				FROM workload_attester_trust_sources WHERE tenant_id=$1 AND id=$2`, tenant, uuid(tenant, 38401)).
				Scan(&ownerIDs, &repositoryIDs)
		}); err != nil {
			t.Fatalf("read restored pins: %v", err)
		}
		if tenant == tenantA && (len(ownerIDs) != 0 || len(repositoryIDs) != 0) {
			t.Fatal("legacy snapshot unexpectedly supplied a pin")
		}
		if tenant == tenantB && (!slices.Equal(ownerIDs, []string{"9007199254740993"}) || !slices.Equal(repositoryIDs, []string{"456"})) {
			t.Fatalf("restored IDs = %v, %v", ownerIDs, repositoryIDs)
		}
	}
}
