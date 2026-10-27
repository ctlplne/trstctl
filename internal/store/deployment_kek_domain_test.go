// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A198: the deployment KEK's single row follows its events in sequence order
// (a replayed older snapshot never moves it back), is read inside every
// tenant's key-domain fence, and refuses a generation without its wrapper.
func TestDeploymentKEKDomainFollowsItsEventsAndIsReadInsideTheTenantFence(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: tenantA}); err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.DeploymentKEKDomain(ctx); err != nil || found {
		t.Fatalf("a deployment that never rotated has a record: found=%v err=%v", found, err)
	}
	apply := func(d store.DeploymentKEKDomain) error {
		return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.ApplyDeploymentKEKSnapshotTx(ctx, tx, d) })
	}
	now := time.Now().UTC()
	rotating := store.DeploymentKEKDomain{
		DomainID: "6c7a0f4e-6d8e-4a51-9a0c-0d8f8c3f2a11", NextGeneration: 1,
		NextWrapperKind: "local_file", NextWrapperID: "deploy-a", NextWrappedKEK: []byte("wrapped-1"),
		OperationID: "op-1", OperationStatus: store.DeploymentKEKOperationRunning, Stage: store.DeploymentKEKStageSettling,
		OperatorTenantID: tenantA, LastTransitionSequence: 5, StartedAt: &now, CreatedAt: now, UpdatedAt: now,
	}
	if err := apply(rotating); err != nil {
		t.Fatal(err)
	}
	completed := rotating
	completed.Generation, completed.WrapperKind, completed.WrapperID, completed.WrappedKEK = 1, "local_file", "deploy-a", []byte("wrapped-1")
	completed.NextGeneration, completed.NextWrapperKind, completed.NextWrapperID, completed.NextWrappedKEK = 0, "", "", nil
	completed.OperationStatus, completed.Stage, completed.LastTransitionSequence = store.DeploymentKEKOperationCompleted, store.DeploymentKEKStageCompleted, 9
	completed.RotatedAt = &now
	if err := apply(completed); err != nil {
		t.Fatal(err)
	}
	if err := apply(rotating); err != nil {
		t.Fatal(err)
	}
	got, found, err := s.DeploymentKEKDomain(ctx)
	if err != nil || !found || got.Generation != 1 || got.Rotating() || got.LastTransitionSequence != 9 || string(got.WrappedKEK) != "wrapped-1" {
		t.Fatalf("after an older replay the record = %+v found=%v err=%v; want generation 1 at sequence 9", got, found, err)
	}

	var fenced *store.DeploymentKEKDomain
	if err := s.WithTenantKeyDomainSharedDeployment(ctx, tenantA, func(domain *store.TenantKeyDomain, deployment *store.DeploymentKEKDomain) error {
		if domain != nil {
			t.Errorf("a legacy tenant read a key domain: %+v", domain)
		}
		if deployment != nil {
			copied := *deployment
			fenced = &copied
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if fenced == nil || fenced.Generation != 1 || fenced.WrapperID != "deploy-a" {
		t.Fatalf("the tenant fence read %+v, want generation 1 under deploy-a", fenced)
	}

	broken := completed
	broken.WrapperKind, broken.WrappedKEK, broken.LastTransitionSequence = "", nil, 12
	if err := apply(broken); err == nil {
		t.Fatal("the table accepted a generation without its wrapper")
	}
	migrated, err := s.TenantsWithMigratedKeyDomainHistory(ctx)
	if err != nil || len(migrated) != 0 {
		t.Fatalf("migrated tenants = %v, %v; want none", migrated, err)
	}
}
