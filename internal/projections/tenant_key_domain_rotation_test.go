// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Rotation snapshots carry the next generation while the rotation runs, the
// completion promotes it and stamps rotated_at, and a snapshot whose next
// generation is missing, skips a generation, or survives outside a rotation is
// refused.
func TestTenantKeyDomainRotationEventsCarryAndPromoteTheNextGeneration(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	p := projections.New(s)

	migrated := tenantKeyDomainSnapshot(store.TenantKeyDomainStatePartial, store.TenantKeyOperationCompleted, 10)
	migrated.LegacyHistoryExposure = store.TenantKeyLegacyExternalArchivesPossible
	if err := p.Apply(ctx, tenantKeyDomainEvent(t, projections.EventTenantKeyDomainMigrationCompleted, 1, migrated)); err != nil {
		t.Fatalf("apply migration completion: %v", err)
	}

	rotationID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	rotating := migrated
	rotating.State = store.TenantKeyDomainStateRotating
	rotating.OperationID = &rotationID
	rotating.OperationKind = store.TenantKeyOperationRotate
	rotating.OperationStatus = store.TenantKeyOperationRunning
	rotating.ProgressCompleted, rotating.ProgressTotal = 0, 13
	rotating.NextGeneration = 2
	rotating.NextWrapperKind, rotating.NextWrapperID = "local_file", "tenant-wrapper-next"
	rotating.NextWrappedDomainKEK = []byte{0x02, 0x7f, 0x80, 0xfe}
	if err := p.Apply(ctx, tenantKeyDomainEvent(t, projections.EventTenantKeyDomainRotationStarted, 2, rotating)); err != nil {
		t.Fatalf("apply rotation start: %v", err)
	}
	started, err := s.GetTenantKeyDomain(ctx, tenantA)
	if err != nil || started.State != store.TenantKeyDomainStateRotating || started.Generation != 1 ||
		started.NextGeneration != 2 || started.NextWrapperID != "tenant-wrapper-next" ||
		!bytes.Equal(started.NextWrappedDomainKEK, rotating.NextWrappedDomainKEK) || started.RotatedAt != nil {
		t.Fatalf("projected rotation start = %+v err=%v", started, err)
	}

	withoutNext := rotating
	withoutNext.NextGeneration, withoutNext.NextWrapperKind, withoutNext.NextWrapperID = 0, "", ""
	withoutNext.NextWrappedDomainKEK = nil
	skipped := rotating
	skipped.NextGeneration = 3
	missingKey := rotating
	missingKey.NextWrappedDomainKEK = nil
	pendingHistory := rotating
	pendingHistory.LegacyHistoryExposure = store.TenantKeyLegacyHotHistoryPending
	for name, bad := range map[string]projections.TenantKeyDomainSnapshot{
		"no next generation": withoutNext, "skipped generation": skipped,
		"missing next key": missingKey, "hot history pending": pendingHistory,
	} {
		if err := p.Apply(ctx, tenantKeyDomainEvent(t, projections.EventTenantKeyDomainRotationProgressed, 3, bad)); err == nil {
			t.Fatalf("rotation progress with %s was projected", name)
		}
	}

	failed := rotating
	failed.OperationStatus = store.TenantKeyOperationFailed
	failed.Retryable = false
	failed.LastErrorCode, failed.LastError = "hot_history_rewrite_failed", "tenant hot-history rewrite failed"
	if err := p.Apply(ctx, tenantKeyDomainEvent(t, projections.EventTenantKeyDomainRotationFailed, 3, failed)); err == nil {
		t.Fatal("a non-retryable failure was projected while both generations are still needed")
	}
	failed.Retryable = true
	if err := p.Apply(ctx, tenantKeyDomainEvent(t, projections.EventTenantKeyDomainRotationFailed, 3, failed)); err != nil {
		t.Fatalf("apply retryable rotation failure: %v", err)
	}

	completed := rotating
	completed.Generation = 2
	completed.WrapperID = rotating.NextWrapperID
	completed.WrappedDomainKEK = rotating.NextWrappedDomainKEK
	completed.NextGeneration, completed.NextWrapperKind, completed.NextWrapperID = 0, "", ""
	completed.NextWrappedDomainKEK = nil
	completed.State = store.TenantKeyDomainStateUnsealed
	completed.OperationStatus = store.TenantKeyOperationCompleted
	completed.ProgressCompleted = completed.ProgressTotal
	completed.Retryable = false
	completed.TransitionEvidenceRefs = []string{"tenant-history://generation-rewrite?changed_events=4"}
	stale := completed
	stale.NextGeneration, stale.NextWrapperKind, stale.NextWrapperID = 3, "local_file", "tenant-wrapper"
	stale.NextWrappedDomainKEK = []byte{0x03}
	if err := p.Apply(ctx, tenantKeyDomainEvent(t, projections.EventTenantKeyDomainRotationCompleted, 4, stale)); err == nil {
		t.Fatal("a completed rotation kept a next generation")
	}
	if err := p.Apply(ctx, tenantKeyDomainEvent(t, projections.EventTenantKeyDomainRotationCompleted, 4, completed)); err != nil {
		t.Fatalf("apply rotation completion: %v", err)
	}
	promoted, err := s.GetTenantKeyDomain(ctx, tenantA)
	wantRotatedAt := time.Date(2026, 7, 31, 1, 2, 4, 0, time.UTC)
	if err != nil || promoted.State != store.TenantKeyDomainStateUnsealed || promoted.Generation != 2 ||
		promoted.WrapperID != "tenant-wrapper-next" || promoted.NextGeneration != 0 ||
		promoted.NextWrappedDomainKEK != nil || promoted.RotatedAt == nil || !promoted.RotatedAt.Equal(wantRotatedAt) ||
		!bytes.Equal(promoted.WrappedDomainKEK, rotating.NextWrappedDomainKEK) {
		t.Fatalf("projected rotation completion = %+v err=%v", promoted, err)
	}
}
