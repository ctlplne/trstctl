// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestPreparedEventSerializesSharedIdentityAcrossTenants(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	data, err := json.Marshal(projections.NotificationRoutingPolicyUpserted{
		ID: uuid.NewString(), Name: "Workload notifications", ScopeKind: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	orch := orchestrator.NewOrchestrator(log, st, nil)
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		tenantID := uuid.NewString()
		go func() {
			<-start
			_, err := orchestrator.EmitPreparedForTest(t.Context(), orch, events.Event{
				Type: projections.EventNotificationRoutingPolicyUpserted, TenantID: tenantID, Data: data,
			})
			results <- err
		}()
	}
	close(start)
	succeeded := 0
	for range 2 {
		err := <-results
		if err == nil {
			succeeded++
		} else if !errors.Is(err, store.ErrNotificationRoutingIdentityConflict) {
			t.Fatalf("unexpected policy admission error: %v", err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("accepted policies = %d, want one", succeeded)
	}
	sequence, err := log.LastSequence(t.Context())
	if err != nil || sequence != 1 {
		t.Fatalf("retained sequence = %d, err=%v, want 1", sequence, err)
	}
}

func TestPreparedEventChecksProjectionBeforePublication(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)
	policyID, firstTenant, secondTenant := uuid.NewString(), uuid.NewString(), uuid.NewString()
	data, err := json.Marshal(projections.NotificationRoutingPolicyUpserted{
		ID: policyID, Name: "Workload notifications", ScopeKind: "manual",
	})
	if err != nil {
		t.Fatal(err)
	}
	orch := orchestrator.NewOrchestrator(log, st, nil)
	first := events.Event{ID: uuid.NewString(), Type: projections.EventNotificationRoutingPolicyUpserted,
		TenantID: firstTenant, Data: data}
	accepted, err := orchestrator.EmitPreparedForTest(ctx, orch, first)
	if err != nil {
		t.Fatalf("first policy: %v", err)
	}
	if repeated, err := orchestrator.EmitPreparedForTest(ctx, orch, first); err != nil || repeated.Sequence != accepted.Sequence {
		t.Fatalf("exact retry sequence=%d err=%v, want %d", repeated.Sequence, err, accepted.Sequence)
	}
	before, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := orchestrator.EmitPreparedForTest(ctx, orch, events.Event{Type: projections.EventNotificationRoutingPolicyUpserted,
		TenantID: secondTenant, Data: data}); !errors.Is(err, store.ErrNotificationRoutingIdentityConflict) {
		t.Fatalf("second policy error = %v, want tenant-owned identity refusal", err)
	}
	after, err := log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("rejected policy advanced event sequence from %d to %d", before, after)
	}
}

func TestPreparedKMIPEnrollmentChecksFingerprintBeforePublication(t *testing.T) {
	ctx := t.Context()
	st := newStore(t)
	log := openLog(t)
	orch := orchestrator.NewOrchestrator(log, st, nil)
	tenantIDs := []string{uuid.NewString(), uuid.NewString()}
	clientIDs := []string{uuid.NewString(), uuid.NewString()}
	emit := func(tenantID, eventType string, payload any) error {
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		_, err = orchestrator.EmitPreparedForTest(ctx, orch, events.Event{
			Type: eventType, TenantID: tenantID, Data: data,
		})
		return err
	}
	for i, tenantID := range tenantIDs {
		if err := emit(tenantID, projections.EventKMIPClientRegistered, projections.KMIPClientRegistered{
			ID: clientIDs[i], Name: "Workload client", EnrollmentHash: "enrollment-reference",
			EnrollmentExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("register client %d: %v", i, err)
		}
	}
	start := make(chan struct{})
	type enrollmentResult struct {
		tenantID string
		err      error
	}
	results := make(chan enrollmentResult, 2)
	for i, tenantID := range tenantIDs {
		clientID := clientIDs[i]
		go func() {
			<-start
			results <- enrollmentResult{tenantID: tenantID, err: emit(tenantID, projections.EventKMIPClientEnrolled, projections.KMIPClientEnrolled{
				ID: clientID, Fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Subject: "CN=Workload client", NotAfter: time.Now().Add(time.Hour),
			})}
		}()
	}
	close(start)
	succeeded := 0
	var acceptedTenant, rejectedTenant, rejectedClient string
	for range 2 {
		result := <-results
		if result.err == nil {
			succeeded++
			acceptedTenant = result.tenantID
			continue
		}
		var pgErr *pgconn.PgError
		if !errors.As(result.err, &pgErr) || pgErr.Code != "23505" {
			t.Fatalf("unexpected enrollment admission error: %v", result.err)
		}
		rejectedTenant = result.tenantID
		for i, tenantID := range tenantIDs {
			if tenantID == rejectedTenant {
				rejectedClient = clientIDs[i]
			}
		}
	}
	if succeeded != 1 {
		t.Fatalf("bound clients = %d, want one", succeeded)
	}
	if sequence, err := log.LastSequence(ctx); err != nil || sequence != 3 {
		t.Fatalf("source head = %d, err=%v, want three accepted events", sequence, err)
	}
	projector := projections.New(st)
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("catch up accepted enrollment: %v", err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild accepted enrollment: %v", err)
	}
	// Retained history from an earlier producer must also stay within its
	// tenant while later accepted events continue through the global cursor.
	conflictingData, err := json.Marshal(projections.KMIPClientEnrolled{
		ID: rejectedClient, Fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Subject: "CN=Workload client", NotAfter: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(ctx, events.Event{
		Type: projections.EventKMIPClientEnrolled, TenantID: rejectedTenant, Data: conflictingData,
	}); err != nil {
		t.Fatal(err)
	}
	if err := emit(acceptedTenant, projections.EventKMIPClientRegistered, projections.KMIPClientRegistered{
		ID: uuid.NewString(), Name: "Next workload client", EnrollmentHash: "next-enrollment-reference",
		EnrollmentExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("catch up retained enrollment: %v", err)
	}
	if checkpoint, err := st.ProjectionCheckpoint(ctx); err != nil || checkpoint != 5 {
		t.Fatalf("projection checkpoint = %d, err=%v, want five", checkpoint, err)
	}
	if quarantined, err := st.ProjectionTenantQuarantined(ctx, rejectedTenant); err != nil || !quarantined {
		t.Fatalf("rejected tenant quarantine = %t, err=%v", quarantined, err)
	}
	if quarantined, err := st.ProjectionTenantQuarantined(ctx, acceptedTenant); err != nil || quarantined {
		t.Fatalf("accepted tenant quarantine = %t, err=%v", quarantined, err)
	}
	if clients, err := st.KMIPClients(ctx, acceptedTenant); err != nil || len(clients) != 2 {
		t.Fatalf("accepted tenant clients = %d, err=%v, want two", len(clients), err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild retained enrollment: %v", err)
	}
	if clients, err := st.KMIPClients(ctx, acceptedTenant); err != nil || len(clients) != 2 {
		t.Fatalf("rebuilt accepted tenant clients = %d, err=%v, want two", len(clients), err)
	}
}
