// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"context"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/store"
)

func TestRecoveryPairProofConsumesOnlyExactTenantOperationAndHashes(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	const operation = "a7770000-0000-4000-8000-000000009741"
	const eventID = "a7770000-0000-4000-8000-000000009742"
	proof := store.RecoveryPairProof{TenantID: tenantA, OperationID: operation,
		EventID: eventID, PairKind: "mutation_receipt", RowID: eventID,
		EventSHA256: strings.Repeat("a", 64), RowSHA256: strings.Repeat("b", 64),
		KeyStateSHA256: strings.Repeat("c", 64)}
	tx, err := s.SystemPool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.InsertRecoveryPairProofTx(ctx, tx, proof); err != nil {
		t.Fatal(err)
	}
	wrong := proof
	wrong.RowSHA256 = strings.Repeat("d", 64)
	if err := s.ConsumeRecoveryPairProofTx(ctx, tx, wrong); err == nil {
		t.Fatal("changed independent row consumed a proof")
	}
	wrong = proof
	wrong.TenantID = tenantB
	if err := s.ConsumeRecoveryPairProofTx(ctx, tx, wrong); err == nil {
		t.Fatal("another tenant consumed a proof")
	}
	wrong = proof
	wrong.OperationID = "a7770000-0000-4000-8000-000000009743"
	if err := s.ConsumeRecoveryPairProofTx(ctx, tx, wrong); err == nil {
		t.Fatal("another recovery operation consumed a proof")
	}
	if err := s.ConsumeRecoveryPairProofTx(ctx, tx, proof); err != nil {
		t.Fatalf("exact proof: %v", err)
	}
	if err := s.ConsumeRecoveryPairProofTx(ctx, tx, proof); err == nil {
		t.Fatal("proof was consumed twice")
	}
}
