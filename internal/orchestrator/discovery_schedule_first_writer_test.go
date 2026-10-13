// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func TestDiscoveryScheduleDistinctCreateCannotAppendSameName(t *testing.T) {
	s, log, projector := recordingSpine(t)
	ctx := t.Context()
	o := orchestrator.NewOrchestrator(log, s, nil)
	source, err := o.UpsertDiscoverySource(ctx, tenantA, store.DiscoverySource{
		ID: "00000000-0000-4000-8000-00000000d201", Kind: "manual", Name: "schedule-first-writer-source",
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := o.UpsertDiscoverySchedule(ctx, tenantA, store.DiscoverySchedule{
		SourceID: source.ID, Name: "one-schedule-name", IntervalSeconds: 300, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	before, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.UpsertDiscoverySchedule(ctx, tenantA, store.DiscoverySchedule{
		SourceID: source.ID, Name: first.Name, IntervalSeconds: 600, Enabled: true,
	}); err == nil {
		t.Fatal("second independent schedule creation with the same name was accepted")
	}
	if after, err := log.LastSequence(ctx); err != nil || after != before {
		t.Fatalf("rejected schedule name appended a durable event: before=%d after=%d err=%v", before, after, err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("accepted schedule history no longer rebuilds: %v", err)
	}
	got, err := s.GetDiscoverySchedule(ctx, tenantA, first.ID)
	if err != nil || got.Name != first.Name || got.IntervalSeconds != first.IntervalSeconds {
		t.Fatalf("first schedule after rebuild = %+v, err=%v", got, err)
	}
}

func TestDiscoveryScheduleLostProjectionFencesSameName(t *testing.T) {
	s, log, projector := recordingSpine(t)
	ctx := t.Context()
	o := orchestrator.NewOrchestrator(log, s, nil)
	source, err := o.UpsertDiscoverySource(ctx, tenantA, store.DiscoverySource{
		ID: "00000000-0000-4000-8000-00000000d211", Kind: "manual", Name: "schedule-lost-projection-source",
	})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AdvanceProjectionCheckpoint(ctx, baseline); err != nil {
		t.Fatal(err)
	}
	_, err = s.SystemPool().Exec(ctx, `CREATE FUNCTION discovery_schedule_lost_projection_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id='11111111-1111-1111-1111-111111111111'::uuid THEN RAISE EXCEPTION 'owned schedule projection rollback'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER discovery_schedule_lost_projection_fail BEFORE INSERT ON discovery_schedules FOR EACH ROW EXECUTE FUNCTION discovery_schedule_lost_projection_fail()`)
	if err != nil {
		t.Fatal(err)
	}
	dropTrigger := func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := s.SystemPool().Exec(cleanup, `DROP TRIGGER IF EXISTS discovery_schedule_lost_projection_fail ON discovery_schedules; DROP FUNCTION IF EXISTS discovery_schedule_lost_projection_fail()`); err != nil {
			t.Errorf("drop owned schedule projection fault: %v", err)
		}
	}
	t.Cleanup(dropTrigger)
	first := store.DiscoverySchedule{
		ID: "00000000-0000-4000-8000-00000000d212", SourceID: source.ID,
		Name: "one-lost-schedule", IntervalSeconds: 300, Enabled: true,
	}
	if _, err := o.UpsertDiscoverySchedule(ctx, tenantA, first); err == nil {
		t.Fatal("owned SQL fault did not interrupt first schedule projection")
	}
	retained, err := log.LastSequence(ctx)
	if err != nil || retained != baseline+1 {
		t.Fatalf("first append head=%d err=%v want=%d", retained, err, baseline+1)
	}
	dropTrigger()
	second := first
	second.ID = "00000000-0000-4000-8000-00000000d213"
	second.IntervalSeconds = 600
	if _, err := o.UpsertDiscoverySchedule(ctx, tenantA, second); !errors.Is(err, store.ErrResourceAdmissionBusy) && !errors.Is(err, orchestrator.ErrDiscoveryScheduleIdentityConflict) {
		t.Fatalf("conflicting second schedule before catch-up = %v", err)
	}
	if head, err := log.LastSequence(ctx); err != nil || head != retained {
		t.Fatalf("second schedule append through gap: head=%d err=%v want=%d", head, err, retained)
	}
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	if _, err := o.UpsertDiscoverySchedule(ctx, tenantA, second); !errors.Is(err, orchestrator.ErrDiscoveryScheduleIdentityConflict) {
		t.Fatalf("second schedule after catch-up = %v", err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoveryScheduleTwoReplicaFencePrecedesAppend(t *testing.T) {
	s, log, projector := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	o := orchestrator.NewOrchestrator(log, s, nil)
	source, err := o.UpsertDiscoverySource(ctx, tenantA, store.DiscoverySource{
		ID: "00000000-0000-4000-8000-00000000d221", Kind: "manual", Name: "schedule-two-replica-source",
	})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AdvanceProjectionCheckpoint(ctx, baseline); err != nil {
		t.Fatal(err)
	}
	peers := make([]*store.Store, 2)
	for i := range peers {
		peers[i], err = store.Open(ctx, testDSN+fmt.Sprintf("?application_name=discovery_schedule_peer_%d", i))
		if err != nil {
			t.Fatal(err)
		}
		defer peers[i].Close()
	}
	const firstID = "00000000-0000-4000-8000-00000000d222"
	held := make(chan struct{})
	release := make(chan struct{})
	gateDone := make(chan error, 1)
	go func() {
		gateDone <- s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "upsert-arbiter\x1fdiscovery_schedules\x1f"+tenantA+"\x1f"+firstID); err != nil {
				return err
			}
			close(held)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	select {
	case <-held:
	case err := <-gateDone:
		t.Fatalf("hold schedule projection: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	first := store.DiscoverySchedule{ID: firstID, SourceID: source.ID, Name: "parallel-schedule", IntervalSeconds: 300, Enabled: true}
	firstDone := make(chan error, 1)
	go func() {
		_, err := orchestrator.NewOrchestrator(log, peers[0], nil).UpsertDiscoverySchedule(ctx, tenantA, first)
		firstDone <- err
	}()
	blocked := 0
	for ctx.Err() == nil {
		//trstctl:system-query — fixture observes only its two owned connection names, no tenant data.
		if err := s.SystemPool().QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE application_name='discovery_schedule_peer_0' AND wait_event_type='Lock' AND wait_event='advisory'`).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked > 0 {
			break
		}
		select {
		case err := <-firstDone:
			t.Fatalf("first writer ended before held projection lock: %v", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	if blocked == 0 {
		t.Fatal("first schedule writer never reached the held projection lock")
	}
	firstHead, err := log.LastSequence(ctx)
	if err != nil || firstHead != baseline+1 {
		t.Fatalf("first schedule event head=%d err=%v want=%d", firstHead, err, baseline+1)
	}
	second := first
	second.ID = "00000000-0000-4000-8000-00000000d223"
	second.IntervalSeconds = 600
	if _, err := orchestrator.NewOrchestrator(log, peers[1], nil).UpsertDiscoverySchedule(ctx, tenantA, second); !errors.Is(err, store.ErrResourceAdmissionBusy) && !errors.Is(err, orchestrator.ErrDiscoveryScheduleIdentityConflict) {
		t.Fatalf("concurrent second writer = %v", err)
	}
	if head, err := log.LastSequence(ctx); err != nil || head != firstHead {
		t.Fatalf("second schedule event appended: head=%d err=%v want=%d", head, err, firstHead)
	}
	close(release)
	released = true
	if err := <-gateDone; err != nil {
		t.Fatal(err)
	}
	if err := <-firstDone; err != nil {
		t.Fatalf("first schedule declaration: %v", err)
	}
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
}
