// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

type workloadSourceRecordingProjection struct {
	sequences []uint64
}

func (p *workloadSourceRecordingProjection) Name() string { return "workload-source-recording" }

func (p *workloadSourceRecordingProjection) Reset(context.Context) error {
	p.sequences = nil
	return nil
}

func (p *workloadSourceRecordingProjection) Apply(_ context.Context, event events.Event) error {
	if event.Type == projections.EventSecretSyncWorkloadIdentityUpserted ||
		event.Type == projections.EventSecretSyncWorkloadIdentityDeleted {
		p.sequences = append(p.sequences, event.Sequence)
	}
	return nil
}

func TestCatchUpPreservesCompletedWorkloadSourceReplacement(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)
	appendEvent := func(eventType string, payload any) events.Event {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		event, err := log.Append(ctx, events.Event{Type: eventType, TenantID: tenantA, Data: data})
		if err != nil {
			t.Fatal(err)
		}
		return event
	}
	appendEvent(projections.EventTenantRegistered, map[string]string{"name": "source replay tenant"})
	trustID := uuid.NewString()
	appendEvent(projections.EventWorkloadAttesterTrustSourceUpserted,
		projections.WorkloadAttesterTrustSourceUpserted{
			ID: trustID, Name: "test trust", Method: "k8s_sat", Issuer: "https://issuer.example.test",
			Audience: "trstctl", JWKS: json.RawMessage(`{"keys":[]}`), Enabled: true,
		})
	recording := &workloadSourceRecordingProjection{}
	projector := projections.New(st, projections.WithEventProjection(recording))
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("initial catch-up: %v", err)
	}
	source := projections.SecretSyncWorkloadIdentitySourceUpserted{
		ID: uuid.NewString(), Name: "first", Provider: "aws",
		RoleARN:  "arn:aws:iam::123456789012:role/trstctl-secret-sync",
		Audience: "trstctl", Subject: "system:serviceaccount:default:web",
		TargetID: "aws-target", WorkloadProofRef: "secret://proof", TrustSourceID: trustID, Enabled: true,
	}
	first := appendEvent(projections.EventSecretSyncWorkloadIdentityUpserted, source)
	for _, event := range []events.Event{
		first,
		appendEvent(projections.EventSecretSyncWorkloadIdentityDeleted,
			projections.SecretSyncWorkloadIdentitySourceDeleted{ID: source.ID}),
	} {
		if err := projector.Apply(ctx, event); err != nil {
			t.Fatalf("inline projection %s: %v", event.Type, err)
		}
	}
	source.ID = uuid.NewString()
	source.Name = "replacement"
	last := appendEvent(projections.EventSecretSyncWorkloadIdentityUpserted, source)
	if err := projector.Apply(ctx, last); err != nil {
		t.Fatalf("inline replacement: %v", err)
	}
	owner, err := st.SecretSyncWorkloadIdentitySourceTargetOwner(ctx, tenantA, source.Provider, source.TargetID)
	if err != nil || owner != source.ID {
		t.Fatalf("projected target owner=%s, err=%v, want %s", owner, err, source.ID)
	}
	for _, event := range []events.Event{first, last} {
		applied, err := st.ProjectionAppliedEventReceipt(ctx, tenantA, event.ID, event.Sequence)
		if err != nil || !applied {
			t.Fatalf("source event %d receipt=%t, err=%v", event.Sequence, applied, err)
		}
	}
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("catch-up after inline projection: %v", err)
	}
	if len(recording.sequences) != 3 {
		t.Fatalf("extension replayed %d source events, want 3", len(recording.sequences))
	}
	if quarantined, err := st.ProjectionTenantQuarantined(ctx, tenantA); err != nil || quarantined {
		t.Fatalf("replacement tenant quarantined=%t, err=%v", quarantined, err)
	}
	if checkpoint, err := st.ProjectionCheckpoint(ctx); err != nil || checkpoint != last.Sequence {
		t.Fatalf("checkpoint=%d, err=%v, want=%d", checkpoint, err, last.Sequence)
	}
	if got, err := st.GetSecretSyncWorkloadIdentitySource(ctx, tenantA, source.ID); err != nil || got.TargetID != source.TargetID {
		t.Fatalf("replacement source=%+v, err=%v", got, err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild source history: %v", err)
	}
	if quarantined, err := st.ProjectionTenantQuarantined(ctx, tenantA); err != nil || quarantined {
		t.Fatalf("rebuilt tenant quarantined=%t, err=%v", quarantined, err)
	}
	if got, err := st.GetSecretSyncWorkloadIdentitySource(ctx, tenantA, source.ID); err != nil || got.TargetID != source.TargetID {
		t.Fatalf("rebuilt source=%+v, err=%v", got, err)
	}
}

func TestCatchUpRequiresExactSourceProjectionReceipt(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log := openLog(t)
	appendEvent := func(eventType string, payload any) events.Event {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		event, err := log.Append(ctx, events.Event{Type: eventType, TenantID: tenantA, Data: data})
		if err != nil {
			t.Fatal(err)
		}
		return event
	}
	appendEvent(projections.EventTenantRegistered, map[string]string{"name": "source receipt tenant"})
	trustID := uuid.NewString()
	appendEvent(projections.EventWorkloadAttesterTrustSourceUpserted,
		projections.WorkloadAttesterTrustSourceUpserted{
			ID: trustID, Name: "test trust", Method: "k8s_sat", Issuer: "https://issuer.example.test",
			Audience: "trstctl", JWKS: json.RawMessage(`{"keys":[]}`), Enabled: true,
		})
	projector := projections.New(st)
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("initial catch-up: %v", err)
	}
	first := projections.SecretSyncWorkloadIdentitySourceUpserted{
		ID: uuid.NewString(), Name: "first", Provider: "aws",
		RoleARN:  "arn:aws:iam::123456789012:role/trstctl-secret-sync",
		Audience: "trstctl", Subject: "system:serviceaccount:default:web",
		TargetID: "aws-target", WorkloadProofRef: "secret://proof", TrustSourceID: trustID, Enabled: true,
	}
	older := appendEvent(projections.EventSecretSyncWorkloadIdentityUpserted, first)
	second := first
	second.ID = uuid.NewString()
	second.Name = "second"
	newer := appendEvent(projections.EventSecretSyncWorkloadIdentityUpserted, second)
	if err := projector.Apply(ctx, newer); err != nil {
		t.Fatalf("inline source: %v", err)
	}
	if applied, err := st.ProjectionAppliedEventReceipt(ctx, tenantA, older.ID, older.Sequence); err != nil || applied {
		t.Fatalf("earlier source receipt=%t, err=%v", applied, err)
	}
	if err := projector.ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("catch-up: %v", err)
	}
	if quarantined, err := st.ProjectionTenantQuarantined(ctx, tenantA); err != nil || !quarantined {
		t.Fatalf("catch-up quarantine=%t, err=%v", quarantined, err)
	}
	if err := projector.Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if quarantined, err := st.ProjectionTenantQuarantined(ctx, tenantA); err != nil || !quarantined {
		t.Fatalf("rebuilt quarantine=%t, err=%v", quarantined, err)
	}
}
