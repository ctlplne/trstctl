// SPDX-License-Identifier: MPL-2.0

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

func approveCeremonyWithEvidenceForTest(t *testing.T, s *store.Store, ceremonyID, custodian, eventID string, seq uint64) int {
	t.Helper()
	ctx := context.Background()
	count, needsEvidence, err := s.ReserveKeyCeremonyApproval(ctx, tenantA, ceremonyID, custodian)
	if err != nil {
		t.Fatalf("ReserveKeyCeremonyApproval(%s): %v", custodian, err)
	}
	if !needsEvidence {
		return count
	}
	count, err = s.AttachKeyCeremonyApprovalEvidence(ctx, tenantA, ceremonyID, custodian, eventID, seq)
	if err != nil {
		t.Fatalf("AttachKeyCeremonyApprovalEvidence(%s): %v", custodian, err)
	}
	return count
}

func TestConsumeKeyCeremonyTxIsSingleUseAndPurposeBound(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTwoTenants(t, s)

	ceremonyID, err := s.CreateKeyCeremony(ctx, tenantA, "root", "alice", 2)
	if err != nil {
		t.Fatalf("CreateKeyCeremony: %v", err)
	}
	approveCeremonyWithEvidenceForTest(t, s, ceremonyID, "bob", "ev-bob", 1)
	if err := consumeCeremonyForTest(t, s, ceremonyID, "root"); !errors.Is(err, store.ErrKeyCeremonyQuorumNotMet) {
		t.Fatalf("consume below quorum = %v, want ErrKeyCeremonyQuorumNotMet", err)
	}
	if err := consumeCeremonyForTest(t, s, ceremonyID, "intermediate:parent"); !errors.Is(err, store.ErrKeyCeremonyPurposeMismatch) {
		t.Fatalf("consume with wrong purpose = %v, want ErrKeyCeremonyPurposeMismatch", err)
	}
	approveCeremonyWithEvidenceForTest(t, s, ceremonyID, "carol", "ev-carol", 2)
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
