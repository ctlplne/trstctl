package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func consumeCeremonyForTest(t *testing.T, s *store.Store, ceremonyID, expectedPurpose string) error {
	t.Helper()
	return s.WithTenant(context.Background(), tenantA, func(tx pgx.Tx) error {
		_, err := s.ConsumeKeyCeremonyTx(context.Background(), tx, tenantA, ceremonyID, expectedPurpose)
		return err
	})
}

func TestConsumeKeyCeremonyTxIsSingleUseAndPurposeBound(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTwoTenants(t, s)

	ceremonyID, err := s.CreateKeyCeremony(ctx, tenantA, "root", "alice", 2)
	if err != nil {
		t.Fatalf("CreateKeyCeremony: %v", err)
	}
	if _, err := s.ApproveKeyCeremony(ctx, tenantA, ceremonyID, "bob"); err != nil {
		t.Fatalf("ApproveKeyCeremony(bob): %v", err)
	}
	if err := consumeCeremonyForTest(t, s, ceremonyID, "root"); !errors.Is(err, store.ErrKeyCeremonyQuorumNotMet) {
		t.Fatalf("consume below quorum = %v, want ErrKeyCeremonyQuorumNotMet", err)
	}
	if err := consumeCeremonyForTest(t, s, ceremonyID, "intermediate:parent"); !errors.Is(err, store.ErrKeyCeremonyPurposeMismatch) {
		t.Fatalf("consume with wrong purpose = %v, want ErrKeyCeremonyPurposeMismatch", err)
	}
	if _, err := s.ApproveKeyCeremony(ctx, tenantA, ceremonyID, "carol"); err != nil {
		t.Fatalf("ApproveKeyCeremony(carol): %v", err)
	}
	if err := consumeCeremonyForTest(t, s, ceremonyID, "root"); err != nil {
		t.Fatalf("consume with quorum and purpose: %v", err)
	}
	got, err := s.GetKeyCeremony(ctx, tenantA, ceremonyID)
	if err != nil {
		t.Fatalf("GetKeyCeremony: %v", err)
	}
	if got.Status != "completed" {
		t.Fatalf("status after consume = %q, want completed", got.Status)
	}
	if err := consumeCeremonyForTest(t, s, ceremonyID, "root"); !errors.Is(err, store.ErrKeyCeremonyNotPending) {
		t.Fatalf("consume completed ceremony = %v, want ErrKeyCeremonyNotPending", err)
	}
}
