// SPDX-License-Identifier: BUSL-1.1
package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// CR-045: the full-restore importer stages hashes under the owner role. The
// ordinary runtime may read only its tenant's rows and may not settle proof.
func TestRestoreOutboxPairsAreTargetLocalTenantProofsCR045(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := context.Background()
	const operation = "a7770000-0000-4000-8000-000000009731"
	pair := store.RestoreOutboxPair{
		TenantID: tenantA, OperationID: operation,
		JobID:         "sync-a7770000-0000-4000-8000-000000009732",
		EventSequence: 7, OutboxID: 3,
		EventPayloadSHA256: strings.Repeat("a", 64),
		RowPayloadSHA256:   strings.Repeat("b", 64),
		EventSealedSHA256:  strings.Repeat("c", 64),
		RowSealedSHA256:    strings.Repeat("d", 64),
	}
	tx, err := s.SystemPool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.StageRestoreOutboxPairTx(ctx, tx, pair); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for _, tenantID := range []string{tenantA, tenantB} {
		pairs, err := s.ListRestoreOutboxPairs(ctx, tenantID, operation)
		if err != nil {
			t.Fatal(err)
		}
		if tenantID == tenantA && (len(pairs) != 1 || pairs[0] != pair) {
			t.Fatalf("tenant A proof rows = %+v", pairs)
		}
		if tenantID == tenantB && len(pairs) != 0 {
			t.Fatalf("tenant B saw tenant A proof rows = %+v", pairs)
		}
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM trstctl_recovery.restore_outbox_pairs
			WHERE tenant_id=$1 AND operation_id=$2`, tenantA, operation)
		return err
	}); err == nil {
		t.Fatal("application role settled full-restore proof")
	}
}

func TestRestoreMarkerWaitsForAuthenticatedOutboxPairsCR045(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := t.Context()
	marker := store.RestoreMarker{
		OperationID:    "a7770000-0000-4000-8000-000000009741",
		ArtifactSHA256: strings.Repeat("e", 64), EventCut: 11,
		DeploymentID: "restore-pair-target",
	}
	if err := s.BeginFullRestore(ctx, marker); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"artifacts_restored", "event_partial", "postgres_imported"} {
		if err := s.AdvanceFullRestore(ctx, marker, phase); err != nil {
			t.Fatal(err)
		}
	}
	pair := store.RestoreOutboxPair{
		TenantID: tenantA, OperationID: marker.OperationID,
		JobID:         "sync-a7770000-0000-4000-8000-000000009742",
		EventSequence: 7, OutboxID: 3,
		EventPayloadSHA256: strings.Repeat("a", 64),
		RowPayloadSHA256:   strings.Repeat("b", 64),
		EventSealedSHA256:  strings.Repeat("c", 64),
		RowSealedSHA256:    strings.Repeat("d", 64),
	}
	tx, err := s.SystemPool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.StageRestoreOutboxPairTx(ctx, tx, pair); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.AdvanceFullRestore(ctx, marker, "pair_verified"); !errors.Is(err, store.ErrRecoveryPairProofMismatch) {
		t.Fatalf("unverified pair advanced restore marker: %v", err)
	}
	if err := s.SettleRestoreOutboxPair(ctx, marker, pair); !errors.Is(err, store.ErrRestoreInProgress) {
		t.Fatalf("ordinary caller settled restore pair: %v", err)
	}
	if err := s.WithFullRestoreOwner(ctx, marker, func(ownerCtx context.Context) error {
		return s.SettleRestoreOutboxPair(ownerCtx, marker, pair)
	}); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"pair_verified", "final_rebuild"} {
		if err := s.AdvanceFullRestore(ctx, marker, phase); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.FinishFullRestore(ctx, marker); err != nil {
		t.Fatal(err)
	}
}
