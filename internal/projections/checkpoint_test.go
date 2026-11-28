// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacy"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestProjectCatchUpReplaysOnlyAfterCheckpoint confirms that a second catch-up
// applies only events after the persisted read-model checkpoint.
func TestProjectCatchUpReplaysOnlyAfterCheckpoint(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	p := projections.New(s)

	// Seed three owners under a tenant and catch up once.
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Acme")})
	for _, o := range []struct{ id, name string }{
		{"00000000-0000-0000-0000-0000000000c1", "one"},
		{"00000000-0000-0000-0000-0000000000c2", "two"},
	} {
		mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated(o.id, o.name)})
	}
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("first catch-up: %v", err)
	}
	if got := ownerCount(t, s, tenantA); got != 2 {
		t.Fatalf("after first catch-up owners = %d, want 2", got)
	}
	head, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := s.ProjectionCheckpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cp != head {
		t.Fatalf("checkpoint = %d after catch-up, want head %d (watermark must track the applied head)", cp, head)
	}

	// Append one more event and catch up again: only the tail event is applied, and
	// the watermark advances to the new head.
	mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated("00000000-0000-0000-0000-0000000000c3", "three")})
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("second catch-up: %v", err)
	}
	if got := ownerCount(t, s, tenantA); got != 3 {
		t.Fatalf("after second catch-up owners = %d, want 3", got)
	}
	newHead, _ := log.LastSequence(ctx)
	cp2, _ := s.ProjectionCheckpoint(ctx)
	if cp2 != newHead {
		t.Fatalf("checkpoint = %d after second catch-up, want new head %d", cp2, newHead)
	}
}

func TestRebuildReplacesStaleRecoveryCursorsBeforeWarmCatchUp(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	p := projections.New(s)
	registered, err := log.Append(ctx, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Acme"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SystemPool().Exec(ctx, `UPDATE projection_checkpoint
		SET applied_seq=133,breakglass_issue_checked_through=133,
		    breakglass_authority_checked_through=133,
		    ca_reprotection_name_checked_through=133 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild short retained log after stale cursor: %v", err)
	}
	for name, read := range map[string]func(context.Context) (uint64, error){
		"issue": s.BreakglassIssueRecoveryCursor, "authority": s.BreakglassAuthorityRecoveryCursor,
	} {
		got, err := read(ctx)
		if err != nil || got != registered.Sequence {
			t.Fatalf("%s cursor after rebuild = %d, err=%v, want %d", name, got, err, registered.Sequence)
		}
	}
	if checked, err := s.CAReprotectionNameRecoveryCursor(ctx); err != nil || checked != 0 {
		t.Fatalf("snapshot or rebuild cannot attest the issuer-name recovery pass: cursor=%d err=%v", checked, err)
	}
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("warm catch-up after rebuilt history: %v", err)
	}
	if checked, err := s.CAReprotectionNameRecoveryCursor(ctx); err != nil || checked != registered.Sequence {
		t.Fatalf("indexed name recovery cursor=%d err=%v, want %d", checked, err, registered.Sequence)
	}
	owner, err := log.Append(ctx, events.Event{
		Type: projections.EventOwnerCreated, TenantID: tenantA,
		Data: ownerCreated("00000000-0000-0000-0000-0000000000d1", "after-rebuild"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("warm tail after rebuilt history: %v", err)
	}
	for name, read := range map[string]func(context.Context) (uint64, error){
		"issue": s.BreakglassIssueRecoveryCursor, "authority": s.BreakglassAuthorityRecoveryCursor,
		"CA name": s.CAReprotectionNameRecoveryCursor,
	} {
		got, err := read(ctx)
		if err != nil || got != owner.Sequence {
			t.Fatalf("%s cursor after warm tail = %d, err=%v, want %d", name, got, err, owner.Sequence)
		}
	}
}

func TestProjectCatchUpAcceptsLegacyProviderAuditPartitionOnlyForProviderEvents(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	p := projections.New(s)
	legacy, err := log.Append(ctx, events.Event{Type: "provider.isolation.drill", TenantID: "provider-control-plane", Data: []byte(`{"passed":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("legacy Provider audit blocked core catch-up: %v", err)
	}
	if checkpoint, err := s.ProjectionCheckpoint(ctx); err != nil || checkpoint != legacy.Sequence {
		t.Fatalf("checkpoint = %d, err=%v, want %d", checkpoint, err, legacy.Sequence)
	}
	current, err := log.Append(ctx, events.Event{Type: "provider.isolation.drill", TenantID: store.ZeroUUID, Data: []byte(`{"passed":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("UUID-scoped Provider audit blocked core catch-up: %v", err)
	}
	if checkpoint, err := s.ProjectionCheckpoint(ctx); err != nil || checkpoint != current.Sequence {
		t.Fatalf("checkpoint = %d, err=%v, want %d", checkpoint, err, current.Sequence)
	}
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatalf("legacy and current Provider audits blocked full core rebuild: %v", err)
	}
	if _, err := log.Append(ctx, events.Event{Type: "provider.future.state_changed", TenantID: "provider-control-plane", Data: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if err := p.ProjectCatchUp(ctx, log); err == nil {
		t.Fatal("unknown Provider event in legacy partition bypassed core tenant validation")
	}
}

func TestProjectCatchUpConcurrentReplicasRefuseActivePrivacyPreparationAUD109(t *testing.T) {
	ctx := context.Background()
	primary := newStore(t)
	replica, err := store.Open(ctx, testDSN)
	if err != nil {
		t.Fatalf("open replica store: %v", err)
	}
	t.Cleanup(func() { replica.Close() })
	log := openLog(t)

	const subject = "catch-up-race@example.com"
	const operationID = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	t.Cleanup(func() {
		_, _ = primary.SystemPool().Exec(context.Background(), `
			DELETE FROM privacy_subject_erasure_preparations
			 WHERE tenant_id = $1 AND operation_id = $2`, tenantA, operationID)
	})
	preparedAt := time.Now().UTC().Round(0)
	_, err = primary.PreparePrivacySubjectErasure(ctx, tenantA, subject,
		store.PrivacySubjectErasurePreparation{
			PrivacySubjectErasure: store.PrivacySubjectErasure{
				TenantID: tenantA, SubjectRef: privacy.SubjectRef(tenantA, subject),
				Reason: "catch-up barrier proof", ErasedAt: preparedAt,
			},
			OperationID:        operationID,
			RequestBinding:     strings.Repeat("2", 64),
			EventID:            "sha256:" + strings.Repeat("3", 64),
			RewriteOperationID: "catch-up-rewrite-operation",
			TargetGeneration:   "catch-up-rewrite-generation",
		})
	if err != nil {
		t.Fatalf("prepare privacy erasure: %v", err)
	}
	mustAppend(t, log, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		Data: tenantRegistered("must-not-project"),
	})

	start := make(chan struct{})
	results := make(chan error, 2)
	for _, projector := range []*projections.Projector{
		projections.New(primary), projections.New(replica),
	} {
		projector := projector
		go func() {
			<-start
			results <- projector.ProjectCatchUp(ctx, log)
		}()
	}
	close(start)
	for range 2 {
		if err := <-results; !errors.Is(err, store.ErrPrivacySubjectErasurePreparationActive) {
			t.Fatalf("concurrent catch-up error = %v, want active-preparation refusal", err)
		}
	}

	checkpoint, err := primary.ProjectionCheckpoint(ctx)
	if err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	if checkpoint != 0 {
		t.Fatalf("checkpoint advanced across active privacy preparation: got %d, want 0", checkpoint)
	}
	if _, err := primary.GetTenant(ctx, tenantA); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("tenant projection crossed active privacy preparation: %v", err)
	}
}

// TestProjectCatchUpSkipsEventsBelowCheckpoint preserves the read-model
// checkpoint boundary when earlier lifecycle history uses an unsupported schema.
func TestProjectCatchUpSkipsEventsBelowCheckpoint(t *testing.T) {
	s := newStore(t)
	log := openLog(t)
	ctx := context.Background()
	p := projections.New(s)

	// A good tenant + owner, caught up so the watermark advances past them.
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Acme")})
	mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated("00000000-0000-0000-0000-0000000000d1", "first")})
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("initial catch-up: %v", err)
	}

	// Set a checkpoint after an unsupported lifecycle event to model a retained
	// history span already covered by a prior read-model snapshot.
	mustAppend(t, log, events.Event{
		Type: projections.EventTenantRegistered, TenantID: tenantA,
		SchemaVersion: 99,
		Data:          tenantRegistered("Updated tenant"),
	})
	coveredHead, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AdvanceProjectionCheckpoint(ctx, coveredHead); err != nil {
		t.Fatalf("advance projection checkpoint: %v", err)
	}

	// A supported owner event follows the checkpoint.
	mustAppend(t, log, events.Event{Type: projections.EventOwnerCreated, TenantID: tenantA, Data: ownerCreated("00000000-0000-0000-0000-0000000000d3", "after")})

	// Catch-up applies only the trailing owner event.
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("catch-up re-processed below the watermark: %v "+
			"(SPINE-007: boot must resume from the checkpoint, not replay from zero)", err)
	}
	// Both supported owner events remain visible.
	if got := ownerCount(t, s, tenantA); got != 2 {
		t.Fatalf("owners = %d, want 2", got)
	}
}

func mustAppend(t *testing.T, log *events.Log, e events.Event) {
	t.Helper()
	if _, err := log.Append(context.Background(), e); err != nil {
		t.Fatalf("append %s: %v", e.Type, err)
	}
}
