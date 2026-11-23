// SPDX-License-Identifier: BUSL-1.1
package projections_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type rewrapAttachedProbe struct{ calls int }

func (*rewrapAttachedProbe) Name() string                { return "rewrap-attached-probe" }
func (*rewrapAttachedProbe) Reset(context.Context) error { return nil }
func (p *rewrapAttachedProbe) Apply(context.Context, events.Event) error {
	p.calls++
	return nil
}

func TestAttachedApplyRejectsCachedEventAfterTenantRewrap(t *testing.T) {
	const tenant = "a7770000-0000-4000-8000-000000009397"
	const name = "admission/attached-apply"
	const eventID = "a7770000-0000-4000-8000-000000009398"
	rig := newVH83Rig(t, tenant, "migrate")
	epoch, err := rig.s.ApplicationSecretTenantEpoch(t.Context(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	vh84Append(t, rig, tenant, epoch, name, eventID, projections.EventApplicationSecretCreated, "native",
		projections.ApplicationSecretMutation{Action: "create", ResultVersion: 1,
			Sealed: rig.seal("attached-value", []byte(tenant+"/secret-store/"+name))}, '1')
	stale, found, err := rig.log.EventByID(t.Context(), eventID)
	if err != nil || !found {
		t.Fatalf("fetch pre-rewrap event found=%t err=%v", found, err)
	}
	rig.rewrap()
	probe := &rewrapAttachedProbe{}
	projector := projections.New(rig.s, projections.WithCanonicalEventSource(rig.log),
		projections.WithEventProjection(probe))
	if err := projector.ApplyEventProjections(t.Context(), stale); !errors.Is(err, projections.ErrCanonicalEventRequired) {
		t.Fatalf("cached attached apply error=%v, want canonical refetch", err)
	}
	if probe.calls != 0 {
		t.Fatalf("attached projection applied stale event %d times", probe.calls)
	}
	current, found, err := rig.log.EventByID(t.Context(), eventID)
	if err != nil || !found {
		t.Fatalf("fetch canonical event found=%t err=%v", found, err)
	}
	if err := projector.ApplyEventProjections(t.Context(), current); err != nil {
		t.Fatalf("current attached apply: %v", err)
	}
	if probe.calls != 1 {
		t.Fatalf("attached projection calls=%d, want one current event", probe.calls)
	}
}

func TestDirectOrdinaryApplyWaitsForExclusiveKeyStateAdmission(t *testing.T) {
	const tenant = "a7770000-0000-4000-8000-000000009395"
	const name = "admission/direct-apply"
	const eventID = "a7770000-0000-4000-8000-000000009396"
	rig := newVH83Rig(t, tenant, "migrate")
	epoch, err := rig.s.ApplicationSecretTenantEpoch(t.Context(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	vh84Append(t, rig, tenant, epoch, name, eventID, projections.EventApplicationSecretCreated, "native",
		projections.ApplicationSecretMutation{Action: "create", ResultVersion: 1,
			Sealed: rig.seal("direct-value", []byte(tenant+"/secret-store/"+name))}, '1')
	rig.rewrap()
	current, found, err := rig.log.EventByID(t.Context(), eventID)
	if err != nil || !found {
		t.Fatalf("current event found=%t err=%v", found, err)
	}
	entered := make(chan struct{})
	projector := projections.New(rig.s, projections.WithCanonicalEventSource(rig.log), projections.WithApplicationSecretReceiptVerifier(
		func(context.Context, string, projections.ApplicationSecretMutation) error {
			close(entered)
			return errors.New("verifier reached")
		}))
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	applyDone := make(chan error, 1)
	err = rig.s.WithGlobalKeyStateAdmission(ctx, store.KeyStateExclusive, func(context.Context) error {
		go func() { applyDone <- projector.Apply(ctx, current) }()
		select {
		case <-entered:
			t.Fatal("ordinary direct Apply reached current-event authentication through exclusive key-state admission")
		case err := <-applyDone:
			t.Fatalf("ordinary direct Apply returned while exclusive admission was held: %v", err)
		case <-time.After(250 * time.Millisecond):
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-applyDone:
		if !errors.Is(err, store.ErrIdempotencyConflict) {
			t.Fatalf("Apply after admission release=%v, want authenticated replay conflict", err)
		}
	case <-ctx.Done():
		t.Fatal("ordinary direct Apply did not resume after exclusive admission released")
	}
}

func testRewrapWaitsForActivePairProof(t *testing.T, mode, tenant string) {
	t.Helper()
	rig := newVH83Rig(t, tenant, mode)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	proofHeld := make(chan struct{})
	releaseProof := make(chan struct{})
	proofDone := make(chan error, 1)
	go func() {
		proofDone <- rig.s.WithGlobalKeyStateAdmission(ctx, store.KeyStateShared, func(admitted context.Context) error {
			tx, err := rig.s.SystemPool().Begin(admitted)
			if err != nil {
				return err
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			if err := rig.s.LockGlobalKeyStateCommitTx(admitted, tx, store.KeyStateShared); err != nil {
				return err
			}
			close(proofHeld)
			select {
			case <-releaseProof:
			case <-admitted.Done():
				return admitted.Err()
			}
			return tx.Commit(admitted)
		})
	}()
	select {
	case <-proofHeld:
	case err := <-proofDone:
		t.Fatalf("hold ordinary A/B pair proof: %v", err)
	case <-ctx.Done():
		t.Fatal("pair proof did not acquire admission")
	}
	transitionDone := make(chan error, 1)
	go func() {
		if mode == "migrate" {
			transitionDone <- rig.tryMigrate()
		} else {
			transitionDone <- rig.tryRotate()
		}
	}()
	select {
	case err := <-transitionDone:
		t.Fatalf("%s transition crossed active pair proof: %v", mode, err)
	case <-time.After(250 * time.Millisecond):
	}
	close(releaseProof)
	if err := <-proofDone; err != nil {
		t.Fatalf("release pair proof: %v", err)
	}
	select {
	case err := <-transitionDone:
		if err != nil {
			t.Fatalf("%s transition after proof release: %v", mode, err)
		}
	case <-ctx.Done():
		t.Fatalf("%s transition did not finish after proof release", mode)
	}
}

func TestTenantMigrationWaitsForActivePairProofAB(t *testing.T) {
	testRewrapWaitsForActivePairProof(t, "migrate", "a7770000-0000-4000-8000-000000009301")
}

func TestDeploymentRotationBeginWaitsForActivePairProofAB(t *testing.T) {
	testRewrapWaitsForActivePairProof(t, "rotate", "a7770000-0000-4000-8000-000000009302")
}

func testRewrapWaitsForOrphanedPairCommit(t *testing.T, mode, tenant string) {
	t.Helper()
	rig := newVH83Rig(t, tenant, mode)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var proofTx pgx.Tx
	err := rig.s.WithGlobalKeyStateAdmission(ctx, store.KeyStateShared, func(admitted context.Context) error {
		var beginErr error
		proofTx, beginErr = rig.s.SystemPool().Begin(admitted)
		if beginErr != nil {
			return beginErr
		}
		return rig.s.LockGlobalKeyStateCommitTx(admitted, proofTx, store.KeyStateShared)
	})
	if err != nil {
		t.Fatalf("hold transaction B after admission A ends: %v", err)
	}
	t.Cleanup(func() { _ = proofTx.Rollback(context.Background()) })
	transitionDone := make(chan error, 1)
	go func() {
		if mode == "migrate" {
			transitionDone <- rig.tryMigrate()
		} else {
			transitionDone <- rig.tryRotate()
		}
	}()
	select {
	case err := <-transitionDone:
		t.Fatalf("%s crossed an uncommitted pair proof after session A ended: %v", mode, err)
	case <-time.After(250 * time.Millisecond):
	}
	if err := proofTx.Rollback(ctx); err != nil {
		t.Fatalf("roll back orphaned pair proof: %v", err)
	}
	select {
	case err := <-transitionDone:
		if err != nil {
			t.Fatalf("%s after pair transaction ended: %v", mode, err)
		}
	case <-ctx.Done():
		t.Fatalf("%s did not finish after pair transaction ended", mode)
	}
}

func TestTenantMigrationWaitsForOrphanedPairProofCommitB(t *testing.T) {
	testRewrapWaitsForOrphanedPairCommit(t, "migrate", "a7770000-0000-4000-8000-000000009303")
}

func TestDeploymentRotationBeginWaitsForOrphanedPairProofCommitB(t *testing.T) {
	testRewrapWaitsForOrphanedPairCommit(t, "rotate", "a7770000-0000-4000-8000-000000009304")
}
