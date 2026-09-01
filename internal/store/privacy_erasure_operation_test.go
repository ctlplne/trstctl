// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/store"
)

func TestPrivacySubjectErasureOperationIsTenantScopedAndImmutable(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const subject = "alice@example.com"
	// Deliberately keep sub-microsecond precision. Linux clocks commonly expose
	// it while PostgreSQL timestamps do not; exact replay must canonicalize the
	// command instead of treating the same event as an idempotency collision.
	now := time.Date(2026, 9, 1, 5, 24, 17, 123456789, time.UTC)

	operation := func(tenantID, operationID, eventID, binding, reason string, sequence uint64) store.PrivacySubjectErasureOperation {
		return store.PrivacySubjectErasureOperation{
			PrivacySubjectErasure: store.PrivacySubjectErasure{
				TenantID: tenantID, SubjectRef: privacy.SubjectRef(tenantID, subject),
				RequestedByRef: privacy.SubjectRef(tenantID, "privacy-admin"),
				Reason:         reason, Counts: map[string]int{"owners": 1}, ErasedAt: now,
			},
			OperationID: operationID, EventID: eventID,
			RequestBinding: binding, EventSequence: sequence,
		}
	}
	apply := func(op store.PrivacySubjectErasureOperation) error {
		return st.WithTenant(ctx, op.TenantID, func(tx pgx.Tx) error {
			return st.ApplyPrivacySubjectErasureOperationTx(ctx, tx, op)
		})
	}

	opA := operation(tenantA, "operation-a", "event-a", "sha256:binding-a", "first", 41)
	opB := operation(tenantB, "operation-b", "event-b", "sha256:binding-b", "other tenant", 42)
	if err := apply(opA); err != nil {
		t.Fatalf("apply tenant A operation: %v", err)
	}
	if err := apply(opB); err != nil {
		t.Fatalf("apply tenant B operation: %v", err)
	}
	if err := apply(opA); err != nil {
		t.Fatalf("reapply exact operation: %v", err)
	}

	gotA, err := st.GetPrivacySubjectErasureOperationByEventID(ctx, tenantA, opA.EventID)
	if err != nil {
		t.Fatalf("load tenant A operation: %v", err)
	}
	if gotA.OperationID != opA.OperationID || gotA.RequestBinding != opA.RequestBinding ||
		gotA.Reason != opA.Reason || gotA.EventSequence != opA.EventSequence ||
		!gotA.ErasedAt.Equal(now.Truncate(time.Microsecond)) {
		t.Fatalf("tenant A operation = %+v, want %+v", gotA, opA)
	}
	if _, err := st.GetPrivacySubjectErasureOperationByEventID(ctx, tenantB, opA.EventID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("tenant B read tenant A event = %v, want pgx.ErrNoRows", err)
	}

	drift := opA
	drift.RequestBinding = "sha256:changed"
	if err := apply(drift); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed binding error = %v, want ErrIdempotencyConflict", err)
	}

	// A later operation updates the subject aggregate. A read-model rebuild
	// preserves both independent operation rows, then replaying their events in
	// order reconstructs the latest aggregate.
	later := operation(tenantA, "operation-later", "event-later", "sha256:binding-later", "later", 51)
	later.ErasedAt = now.Add(time.Minute)
	canonicalLaterErasedAt := later.ErasedAt.Truncate(time.Microsecond)
	if err := apply(later); err != nil {
		t.Fatalf("apply later operation: %v", err)
	}
	if err := apply(opA); err != nil {
		t.Fatalf("redeliver older operation after later inline completion: %v", err)
	}
	beforeRebuild, err := st.ListPrivacySubjectErasuresPage(ctx, tenantA, "", 10)
	if err != nil {
		t.Fatalf("list subject aggregate before rebuild: %v", err)
	}
	if len(beforeRebuild) != 1 || beforeRebuild[0].Reason != later.Reason ||
		!beforeRebuild[0].ErasedAt.Equal(canonicalLaterErasedAt) {
		t.Fatalf("older redelivery regressed newer subject aggregate: %+v", beforeRebuild)
	}
	if err := st.TruncateReadModel(ctx); err != nil {
		t.Fatalf("truncate event read model: %v", err)
	}
	if _, err := st.GetPrivacySubjectErasureOperationByEventID(ctx, tenantA, opA.EventID); err != nil {
		t.Fatalf("independent operation did not survive read-model truncate: %v", err)
	}
	if err := apply(opA); err != nil {
		t.Fatalf("replay older operation: %v", err)
	}
	if err := apply(later); err != nil {
		t.Fatalf("replay later operation: %v", err)
	}
	erasures, err := st.ListPrivacySubjectErasuresPage(ctx, tenantA, "", 10)
	if err != nil {
		t.Fatalf("list subject aggregate: %v", err)
	}
	if len(erasures) != 1 || erasures[0].Reason != later.Reason ||
		!erasures[0].ErasedAt.Equal(canonicalLaterErasedAt) {
		t.Fatalf("ordered rebuild did not restore latest subject aggregate: %+v", erasures)
	}
}
