// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestDiscoverySourceCreationIgnoresUnrelatedProjectionLag(t *testing.T) {
	s, log, projector := recordingSpine(t)
	ctx := t.Context()
	baseline, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AdvanceProjectionCheckpoint(ctx, baseline); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{
		Type: projections.EventDiscoverySegmentUpserted, TenantID: tenantA,
		Data: []byte(`{"id":"00000000-0000-4000-8000-00000000d120","name":"unrelated-segment","ranges":[],"staleness_hours":24}`),
	}); err != nil {
		t.Fatal(err)
	}
	const sourceID = "00000000-0000-4000-8000-00000000d121"
	created, err := orchestrator.NewOrchestrator(log, s, nil).UpsertDiscoverySource(ctx, tenantA,
		store.DiscoverySource{ID: sourceID, Kind: "manual", Name: "new-source-despite-unrelated-lag"})
	if err != nil || created.ID != sourceID {
		t.Fatalf("source creation behind unrelated segment event = %+v, err=%v", created, err)
	}
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetDiscoverySourceByName(ctx, tenantA, created.Name); err != nil || got.ID != sourceID {
		t.Fatalf("source after ordered catch-up = %+v, err=%v", got, err)
	}
}

func TestDiscoverySourceLostProjectionFencesDifferentFirstWriter(t *testing.T) {
	s, log, projector := recordingSpine(t)
	ctx := t.Context()
	baseline, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AdvanceProjectionCheckpoint(ctx, baseline); err != nil {
		t.Fatal(err)
	}
	const firstID = "00000000-0000-4000-8000-00000000d101"
	const secondID = "00000000-0000-4000-8000-00000000d102"
	_, err = s.SystemPool().Exec(ctx, `CREATE FUNCTION discovery_source_lost_projection_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id='11111111-1111-1111-1111-111111111111'::uuid THEN RAISE EXCEPTION 'owned source projection rollback'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER discovery_source_lost_projection_fail BEFORE INSERT ON discovery_sources FOR EACH ROW EXECUTE FUNCTION discovery_source_lost_projection_fail()`)
	if err != nil {
		t.Fatal(err)
	}
	dropTrigger := func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := s.SystemPool().Exec(cleanup, `DROP TRIGGER IF EXISTS discovery_source_lost_projection_fail ON discovery_sources; DROP FUNCTION IF EXISTS discovery_source_lost_projection_fail()`); err != nil {
			t.Errorf("drop owned projection fault: %v", err)
		}
	}
	t.Cleanup(dropTrigger)
	o := orchestrator.NewOrchestrator(log, s, nil)
	first := store.DiscoverySource{ID: firstID, Kind: "manual", Name: "one-source-identity"}
	if _, err := o.UpsertDiscoverySource(ctx, tenantA, first); err == nil {
		t.Fatal("the owned SQL fault did not interrupt the first source projection")
	}
	retainedHead, err := log.LastSequence(ctx)
	if err != nil || retainedHead != baseline+1 {
		t.Fatalf("first append head = %d, err %v; want %d", retainedHead, err, baseline+1)
	}
	dropTrigger()
	second := store.DiscoverySource{ID: secondID, Kind: "ct_log", Name: first.Name}
	if _, err := o.UpsertDiscoverySource(ctx, tenantA, second); !errors.Is(err, store.ErrResourceAdmissionBusy) && !errors.Is(err, orchestrator.ErrDiscoverySourceIdentityConflict) {
		t.Fatalf("different first writer after retained unprojected source = %v, want a safe retryable refusal or identity conflict", err)
	}
	if head, err := log.LastSequence(ctx); err != nil || head != retainedHead {
		t.Fatalf("second declaration appended through projection gap: head=%d err=%v, want %d", head, err, retainedHead)
	}
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	if _, err := o.UpsertDiscoverySource(ctx, tenantA, second); !errors.Is(err, orchestrator.ErrDiscoverySourceIdentityConflict) {
		t.Fatalf("different first writer after catch-up = %v, want identity conflict", err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDiscoverySourceByName(ctx, tenantA, first.Name)
	if err != nil || got.ID != firstID || got.Kind != first.Kind {
		t.Fatalf("replay rebuilt source = %+v, err=%v; want original", got, err)
	}
}

func TestDiscoverySourceTwoReplicaFirstWriterFencePrecedesAppend(t *testing.T) {
	s, log, projector := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	baseline, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AdvanceProjectionCheckpoint(ctx, baseline); err != nil {
		t.Fatal(err)
	}
	const firstID = "00000000-0000-4000-8000-00000000d111"
	const secondID = "00000000-0000-4000-8000-00000000d112"
	peers := make([]*store.Store, 2)
	for i := range peers {
		peers[i], err = store.Open(ctx, testDSN+fmt.Sprintf("?application_name=discovery_first_writer_peer_%d", i))
		if err != nil {
			t.Fatal(err)
		}
		defer peers[i].Close()
	}
	held := make(chan struct{})
	release := make(chan struct{})
	gateDone := make(chan error, 1)
	go func() {
		gateDone <- s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "upsert-arbiter\x1fdiscovery_sources\x1f"+tenantA+"\x1f"+firstID); err != nil {
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
		t.Fatalf("hold projection lock: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	first := store.DiscoverySource{ID: firstID, Kind: "manual", Name: "parallel-first-source"}
	firstDone := make(chan error, 1)
	go func() {
		_, err := orchestrator.NewOrchestrator(log, peers[0], nil).UpsertDiscoverySource(ctx, tenantA, first)
		firstDone <- err
	}()
	blocked := 0
	for ctx.Err() == nil {
		//trstctl:system-query — fixture observes only its two owned connection names, no tenant data.
		if err := s.SystemPool().QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE application_name='discovery_first_writer_peer_0' AND wait_event_type='Lock' AND wait_event='advisory'`).Scan(&blocked); err != nil {
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
		t.Fatal("first writer never reached the held projection lock")
	}
	afterFirst, err := log.LastSequence(ctx)
	if err != nil || afterFirst != baseline+1 {
		t.Fatalf("first writer event head=%d err=%v, want %d", afterFirst, err, baseline+1)
	}
	second := store.DiscoverySource{ID: secondID, Kind: "ct_log", Name: first.Name}
	_, secondErr := orchestrator.NewOrchestrator(log, peers[1], nil).UpsertDiscoverySource(ctx, tenantA, second)
	if !errors.Is(secondErr, store.ErrResourceAdmissionBusy) && !errors.Is(secondErr, orchestrator.ErrDiscoverySourceIdentityConflict) {
		t.Fatalf("concurrent second first writer = %v, want safe refusal", secondErr)
	}
	if head, err := log.LastSequence(ctx); err != nil || head != afterFirst {
		t.Fatalf("second writer appended through held first writer: head=%d err=%v want=%d", head, err, afterFirst)
	}
	close(release)
	released = true
	if err := <-gateDone; err != nil {
		t.Fatal(err)
	}
	if err := <-firstDone; err != nil {
		t.Fatalf("first source declaration: %v", err)
	}
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDiscoverySourceByName(ctx, tenantA, first.Name)
	if err != nil || got.ID != firstID || got.Kind != first.Kind {
		t.Fatalf("replay rebuilt source = %+v, err=%v; want first writer", got, err)
	}
}
