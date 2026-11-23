// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/store"
)

func TestRecoveryDomainResolverReadsOnlyItsValidatedOperationSnapshot(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	const operation = "a7770000-0000-4000-8000-000000009711"
	const otherOperation = "a7770000-0000-4000-8000-000000009712"
	const eventID = "a7770000-0000-4000-8000-000000009713"
	want := store.TenantKeyDomain{TenantID: tenantA,
		DomainID: "a7770000-0000-4000-8000-000000009714", Generation: 2,
		WrappedDomainKEK: []byte("wrapped-key-material"), LastTransitionEventID: eventID,
		LastTransitionSequence: 7}
	if err := s.StageTenantKeyRecoveryLifecycle(ctx, operation, tenantA,
		"a7770000-0000-4000-8000-000000009715", 1, true); err != nil {
		t.Fatal(err)
	}
	if err := s.StageTenantKeyRecoverySnapshot(ctx, operation, want); err != nil {
		t.Fatal(err)
	}
	reader, err := s.NewTenantKeyRecoveryDomainStore(operation)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.WithTenantKeyDomainShared(ctx, tenantA, func(got *store.TenantKeyDomain) error {
		if got == nil || got.DomainID != want.DomainID || got.Generation != 2 ||
			!bytes.Equal(got.WrappedDomainKEK, want.WrappedDomainKEK) {
			t.Fatalf("recovery snapshot = %+v", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	other, err := s.NewTenantKeyRecoveryDomainStore(otherOperation)
	if err != nil {
		t.Fatal(err)
	}
	for _, read := range []struct {
		reader *store.TenantKeyRecoveryDomainStore
		tenant string
	}{{reader, tenantB}, {other, tenantA}} {
		if err := read.reader.WithTenantKeyDomainShared(ctx, read.tenant, func(got *store.TenantKeyDomain) error {
			if got != nil {
				t.Fatalf("another tenant or operation received a key snapshot: %+v", got)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.ClearTenantKeyRecoverySnapshots(ctx, tenantA, operation); err != nil {
		t.Fatal(err)
	}
	if err := reader.WithTenantKeyDomainShared(ctx, tenantA, func(got *store.TenantKeyDomain) error {
		if got != nil {
			t.Fatal("consumed recovery snapshot remained readable")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryDomainResolverDoesNotResurrectOffboardedKeyState(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	const operation = "a7770000-0000-4000-8000-000000009721"
	if err := s.StageTenantKeyRecoveryLifecycle(ctx, operation, tenantA,
		"a7770000-0000-4000-8000-000000009722", 1, true); err != nil {
		t.Fatal(err)
	}
	if err := s.StageTenantKeyRecoverySnapshot(ctx, operation, store.TenantKeyDomain{
		TenantID: tenantA, DomainID: "a7770000-0000-4000-8000-000000009723",
		LastTransitionEventID:  "a7770000-0000-4000-8000-000000009724",
		LastTransitionSequence: 2,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.StageTenantKeyRecoveryLifecycle(ctx, operation, tenantA,
		"a7770000-0000-4000-8000-000000009725", 3, false); err != nil {
		t.Fatal(err)
	}
	reader, err := s.NewTenantKeyRecoveryDomainStore(operation)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.WithTenantKeyDomainShared(ctx, tenantA, func(got *store.TenantKeyDomain) error {
		if got != nil {
			t.Fatalf("offboarded key state was resurrected: %+v", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.StageTenantKeyRecoverySnapshot(ctx, operation, store.TenantKeyDomain{
		TenantID: tenantA, DomainID: "a7770000-0000-4000-8000-000000009727",
		LastTransitionEventID:  "a7770000-0000-4000-8000-000000009728",
		LastTransitionSequence: 4,
	}); err == nil {
		t.Fatal("key snapshot after offboard but before registration was accepted")
	}
	if err := s.StageTenantKeyRecoveryLifecycle(ctx, operation, tenantA,
		"a7770000-0000-4000-8000-000000009726", 5, true); err != nil {
		t.Fatal(err)
	}
	if err := reader.WithTenantKeyDomainShared(ctx, tenantA, func(got *store.TenantKeyDomain) error {
		if got != nil {
			t.Fatalf("new registration inherited old key state: %+v", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
