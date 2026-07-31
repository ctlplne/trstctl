// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func tenantKeyDomainFixture(tenantID string) store.TenantKeyDomain {
	operationID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	return store.TenantKeyDomain{
		TenantID:                   tenantID,
		DomainID:                   "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		Generation:                 1,
		ProtectionMode:             store.TenantKeyProtectionTenantDomain,
		State:                      store.TenantKeyDomainStateMigrating,
		WrapperKind:                "local_file",
		WrapperID:                  "tenant-wrapper",
		WrappedDomainKEK:           []byte{0x00, 0x7f, 0x80, 0xff},
		OperationID:                &operationID,
		OperationKind:              store.TenantKeyOperationMigrate,
		OperationStatus:            store.TenantKeyOperationRunning,
		MigrationStage:             "postgres_rows",
		ProgressCompleted:          3,
		ProgressTotal:              12,
		ProgressCursor:             `{"table":"secret_store","after":"alpha"}`,
		Retryable:                  true,
		LegacyHistoryExposure:      store.TenantKeyLegacyHotHistoryPending,
		LastTransitionEventID:      "EVT-tenant-domain-started",
		LastTransitionType:         "tenant.key_domain.migration_started",
		LastTransitionActor:        "operator@example.test",
		LastTransitionAt:           time.Date(2026, 7, 31, 1, 2, 3, 0, time.UTC),
		LastTransitionEvidenceRefs: []string{"audit://tenant-domain/start"},
		LastTransitionSequence:     41,
		CreatedAt:                  time.Date(2026, 7, 31, 1, 2, 3, 0, time.UTC),
		UpdatedAt:                  time.Date(2026, 7, 31, 1, 2, 3, 0, time.UTC),
	}
}

// TestTenantKeyDomainRLSAndWrappedKeyBytes proves the independently wrapped
// domain record is tenant-confined at PostgreSQL, including its binary wrapped
// key. Tenant B cannot select or overwrite tenant A's row even when it supplies
// A's tenant_id to the repository sink.
func TestTenantKeyDomainRLSAndWrappedKeyBytes(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTwoTenants(t, s)

	want := tenantKeyDomainFixture(tenantA)
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyTenantKeyDomainSnapshotTx(ctx, tx, want)
	}); err != nil {
		t.Fatalf("project tenant A key domain: %v", err)
	}

	var got store.TenantKeyDomain
	if err := s.WithTenantKeyDomainShared(ctx, tenantA, func(domain *store.TenantKeyDomain) error {
		if domain == nil {
			return errors.New("tenant A projected domain was reported as legacy")
		}
		got = *domain
		return nil
	}); err != nil {
		t.Fatalf("WithTenantKeyDomainShared(A): %v", err)
	}
	if !bytes.Equal(got.WrappedDomainKEK, want.WrappedDomainKEK) {
		t.Fatalf("wrapped domain KEK = %x, want %x (must round-trip as bytes)", got.WrappedDomainKEK, want.WrappedDomainKEK)
	}
	if got.ProgressCursor != want.ProgressCursor || got.LastTransitionEventID != want.LastTransitionEventID {
		t.Fatalf("key-domain progress/evidence = %+v, want fixture %+v", got, want)
	}

	if _, err := s.GetTenantKeyDomain(ctx, tenantB); !errors.Is(err, store.ErrTenantKeyDomainNotFound) {
		t.Fatalf("GetTenantKeyDomain(B) err = %v, want ErrTenantKeyDomainNotFound", err)
	}

	crossTenant := tenantKeyDomainFixture(tenantA)
	crossTenant.State = store.TenantKeyDomainStateSealed
	if err := s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error {
		return s.ApplyTenantKeyDomainSnapshotTx(ctx, tx, crossTenant)
	}); err == nil {
		t.Fatal("tenant B projected a row carrying tenant A's tenant_id; RLS WITH CHECK must reject it")
	}
	unchanged, err := s.GetTenantKeyDomain(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.State != store.TenantKeyDomainStateMigrating {
		t.Fatalf("tenant A state = %q after tenant B overwrite attempt, want migrating", unchanged.State)
	}
}

// TestTenantKeyDomainSharedLockFencesExclusiveTransition proves the lock used by
// ordinary tenant crypto work is shared across replicas, while a seal/migration
// transition takes the matching exclusive lock. Equal operations in another
// tenant use a different lock identity and keep running.
func TestTenantKeyDomainSharedLockFencesExclusiveTransition(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTwoTenants(t, s)

	sharedHeld := make(chan struct{})
	releaseShared := make(chan struct{})
	sharedDone := make(chan error, 1)
	go func() {
		sharedDone <- s.WithTenantKeyDomainShared(ctx, tenantA, func(domain *store.TenantKeyDomain) error {
			if domain != nil {
				return errors.New("missing key-domain row was not represented as legacy deployment protection")
			}
			close(sharedHeld)
			<-releaseShared
			return nil
		})
	}()
	<-sharedHeld

	exclusiveDone := make(chan error, 1)
	go func() {
		exclusiveDone <- s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			return s.LockTenantKeyDomainExclusiveTx(ctx, tx, tenantA)
		})
	}()
	select {
	case err := <-exclusiveDone:
		t.Fatalf("tenant A exclusive transition passed an in-flight shared operation: %v", err)
	case <-time.After(100 * time.Millisecond):
		// Expected: PostgreSQL is holding the exclusive transition at the fence.
	}

	otherTenantDone := make(chan error, 1)
	go func() {
		otherTenantDone <- s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error {
			return s.LockTenantKeyDomainExclusiveTx(ctx, tx, tenantB)
		})
	}()
	select {
	case err := <-otherTenantDone:
		if err != nil {
			t.Fatalf("tenant B independent exclusive transition: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tenant B transition blocked behind tenant A; lock identity is not tenant-scoped")
	}

	close(releaseShared)
	if err := <-sharedDone; err != nil {
		t.Fatalf("release tenant A shared lock: %v", err)
	}
	select {
	case err := <-exclusiveDone:
		if err != nil {
			t.Fatalf("tenant A exclusive transition after drain: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tenant A exclusive transition stayed blocked after shared work drained")
	}
}

func TestTenantKeyDomainLockRejectsCrossTenantTransactionScope(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTwoTenants(t, s)

	err := s.WithTenant(ctx, tenantB, func(tx pgx.Tx) error {
		return s.LockTenantKeyDomainExclusiveTx(ctx, tx, tenantA)
	})
	if err == nil || !strings.Contains(err.Error(), "does not match transaction scope") {
		t.Fatalf("tenant B lock of tenant A error = %v, want scope rejection", err)
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.LockTenantKeyDomainExclusiveTx(ctx, tx, tenantA)
	}); err != nil {
		t.Fatalf("tenant A could not acquire its own lock after rejected cross-tenant attempt: %v", err)
	}
}

func TestTenantKeyDomainSchemaRequiresOperationAndPositiveSequence(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTwoTenants(t, s)

	tests := []struct {
		name   string
		change func(*store.TenantKeyDomain)
	}{
		{
			name: "missing operation id",
			change: func(domain *store.TenantKeyDomain) {
				domain.OperationID = nil
			},
		},
		{
			name: "zero transition sequence",
			change: func(domain *store.TenantKeyDomain) {
				domain.LastTransitionSequence = 0
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			domain := tenantKeyDomainFixture(tenantA)
			test.change(&domain)
			if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
				return s.ApplyTenantKeyDomainSnapshotTx(ctx, tx, domain)
			}); err == nil {
				t.Fatalf("schema accepted %s", test.name)
			}
		})
	}
}

// TestTenantKeyDomainOffboardErasesOnlyNamedTenant pins the offboarding catalog:
// independently wrapped custody metadata and wrapped key bytes leave with tenant
// A, while tenant B's cryptographic domain remains byte-for-byte intact.
func TestTenantKeyDomainOffboardErasesOnlyNamedTenant(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTwoTenants(t, s)

	for _, tenantID := range []string{tenantA, tenantB} {
		domain := tenantKeyDomainFixture(tenantID)
		if err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			return s.ApplyTenantKeyDomainSnapshotTx(ctx, tx, domain)
		}); err != nil {
			t.Fatalf("seed key domain for %s: %v", tenantID, err)
		}
	}

	attestation, err := s.OffboardTenant(ctx, tenantA)
	if err != nil {
		t.Fatalf("OffboardTenant(A): %v", err)
	}
	if got := attestation.Deleted["tenant_key_domains"]; got != 1 {
		t.Fatalf("tenant_key_domains deleted rows = %d, want 1", got)
	}
	if _, err := s.GetTenantKeyDomain(ctx, tenantA); !errors.Is(err, store.ErrTenantKeyDomainNotFound) {
		t.Fatalf("tenant A key domain survived offboarding: %v", err)
	}
	gotB, err := s.GetTenantKeyDomain(ctx, tenantB)
	if err != nil {
		t.Fatalf("tenant B key domain after A offboard: %v", err)
	}
	if !bytes.Equal(gotB.WrappedDomainKEK, tenantKeyDomainFixture(tenantB).WrappedDomainKEK) {
		t.Fatalf("tenant B wrapped KEK changed during A offboard: %x", gotB.WrappedDomainKEK)
	}
}
