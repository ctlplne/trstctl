// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventstest"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/tenancy"
)

// Rebuild projects within one SQL transaction. The conflict check must see
// the first source staged in that transaction, even with no preexisting marker.
func TestCR359AtomicRebuildFindsDuplicateTargetInStagedRows(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log, err := eventstest.OpenFixture(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	appendEvent := func(eventType, tenantID string, payload any) {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	appendEvent(projections.EventTenantRegistered, tenantA, map[string]string{"name": "conflicting tenant"})
	appendEvent(projections.EventTenantRegistered, tenantB, map[string]string{"name": "healthy tenant"})
	trustID := uuid.NewString()
	appendEvent(projections.EventWorkloadAttesterTrustSourceUpserted, tenantA,
		projections.WorkloadAttesterTrustSourceUpserted{
			ID: trustID, Name: "test trust", Method: "k8s_sat", Issuer: "https://issuer.example.test",
			Audience: "trstctl", JWKS: json.RawMessage(`{"keys":[]}`), Enabled: true,
		})
	first := projections.SecretSyncWorkloadIdentitySourceUpserted{
		ID: uuid.NewString(), Name: "first", Provider: "aws",
		RoleARN:  "arn:aws:iam::123456789012:role/trstctl-secret-sync",
		Audience: "trstctl", Subject: "system:serviceaccount:default:web",
		TargetID: "aws-target", WorkloadProofRef: "secret://proof", TrustSourceID: trustID, Enabled: true,
	}
	appendEvent(projections.EventSecretSyncWorkloadIdentityUpserted, tenantA, first)
	if err := projections.New(st).ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("clean first source catch-up: %v", err)
	}
	tailCtx, cancelTail := context.WithCancel(ctx)
	tailDone := make(chan error, 1)
	go func() { tailDone <- projections.NewTailWorker(log, projections.New(st), nil, time.Second).Run(tailCtx) }()
	defer cancelTail()
	duplicate := first
	duplicate.ID = uuid.NewString()
	duplicate.Name = "second"
	appendEvent(projections.EventSecretSyncWorkloadIdentityUpserted, tenantA, duplicate)
	appendEvent(projections.EventOwnerCreated, tenantB, json.RawMessage(ownerCreated(uuid.NewString(), "later owner")))
	projected := false
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if ownerCount(t, st, tenantB) == 1 {
			projected = true
			break
		}
	}
	if !projected {
		t.Error("healthy tenant owner was blocked by historical duplicate in live tail")
	}
	health, err := st.ProjectionTailHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if health.FailedSequence != 0 {
		t.Errorf("historical duplicate failed shared tail at sequence %d", health.FailedSequence)
	}
	cancelTail()
	select {
	case err := <-tailDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("tail stopped with error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Error("tail did not stop after cancellation")
	}
	// A restored database can retain the old stream but lose the quarantine
	// marker. Atomic rebuild must rediscover the collision from staged rows.
	if _, err := st.SystemPool().Exec(ctx,
		`DELETE FROM projection_tenant_quarantines WHERE tenant_id=$1`, tenantA); err != nil {
		t.Fatal(err)
	}

	if err := projections.New(st).Rebuild(ctx, log); err != nil {
		t.Fatalf("duplicate source blocked atomic rebuild: %v", err)
	}
	if count := ownerCount(t, st, tenantB); count != 1 {
		t.Errorf("healthy tenant owner count after rebuild = %d, want 1", count)
	}
	if err := st.RequireLiveTenantService(ctx, tenantA); !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Errorf("conflicting tenant service admission = %v", err)
	}
	if quarantined, err := st.ProjectionTenantQuarantined(ctx, tenantA); err != nil || !quarantined {
		t.Errorf("atomic rebuild did not persist conflict quarantine: quarantined=%v err=%v", quarantined, err)
	}
}
