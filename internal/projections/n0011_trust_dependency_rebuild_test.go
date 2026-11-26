// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventstest"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/tenancy"
)

func TestN0011HistoricalTrustDeleteQuarantinesOnlyItsTenant(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log, err := eventstest.OpenFixture(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	appendEvent := func(kind, tenantID string, payload any) {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(ctx, events.Event{Type: kind, TenantID: tenantID, Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	appendEvent(projections.EventTenantRegistered, tenantA, map[string]string{"name": "dependent"})
	appendEvent(projections.EventTenantRegistered, tenantB, map[string]string{"name": "healthy"})
	trustID := uuid.NewString()
	appendEvent(projections.EventWorkloadAttesterTrustSourceUpserted, tenantA,
		projections.WorkloadAttesterTrustSourceUpserted{
			ID: trustID, Name: "test trust", Method: "k8s_sat", Issuer: "https://issuer.example.test",
			Audience: "trstctl", JWKS: json.RawMessage(`{"keys":[]}`), Enabled: true,
		})
	appendEvent(projections.EventSecretSyncWorkloadIdentityUpserted, tenantA,
		projections.SecretSyncWorkloadIdentitySourceUpserted{
			ID: uuid.NewString(), Name: "dependent", Provider: "aws",
			RoleARN:  "arn:aws:iam::123456789012:role/trstctl-secret-sync",
			Audience: "trstctl", Subject: "system:serviceaccount:default:web",
			TargetID: "aws-target", WorkloadProofRef: "secret://proof", TrustSourceID: trustID, Enabled: true,
		})
	appendEvent(projections.EventWorkloadAttesterTrustSourceDeleted, tenantA,
		projections.WorkloadAttesterTrustSourceDeleted{ID: trustID})
	appendEvent(projections.EventOwnerCreated, tenantB, json.RawMessage(ownerCreated(uuid.NewString(), "later owner")))
	if err := projections.New(st).ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("old FK poison blocked global catch-up: %v", err)
	}
	if n := ownerCount(t, st, tenantB); n != 1 {
		t.Fatalf("healthy tenant owner count = %d, want 1", n)
	}
	if err := st.RequireLiveTenantService(ctx, tenantA); !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Fatalf("dependent tenant service admission = %v", err)
	}
	if err := projections.New(st).Rebuild(ctx, log); err != nil {
		t.Fatalf("old FK poison blocked rebuild: %v", err)
	}
	if n := ownerCount(t, st, tenantB); n != 1 {
		t.Fatalf("healthy tenant owner count after rebuild = %d, want 1", n)
	}
}

func TestN0011HistoricalWorkloadSourceWithDeletedTrustQuarantinesOnlyItsTenant(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	log, err := eventstest.OpenFixture(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	appendEvent := func(kind, tenantID string, payload any) {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(ctx, events.Event{Type: kind, TenantID: tenantID, Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	appendEvent(projections.EventTenantRegistered, tenantA, map[string]string{"name": "missing trust"})
	appendEvent(projections.EventTenantRegistered, tenantB, map[string]string{"name": "healthy"})
	appendEvent(projections.EventSecretSyncWorkloadIdentityUpserted, tenantA,
		projections.SecretSyncWorkloadIdentitySourceUpserted{
			ID: uuid.NewString(), Name: "orphan", Provider: "aws",
			RoleARN:  "arn:aws:iam::123456789012:role/trstctl-secret-sync",
			Audience: "trstctl", Subject: "system:serviceaccount:default:web",
			TargetID: "aws-target", WorkloadProofRef: "secret://proof", TrustSourceID: uuid.NewString(), Enabled: true,
		})
	appendEvent(projections.EventOwnerCreated, tenantB, json.RawMessage(ownerCreated(uuid.NewString(), "later owner")))
	if err := projections.New(st).ProjectCatchUp(ctx, log); err != nil {
		t.Fatalf("old orphan source blocked global catch-up: %v", err)
	}
	if n := ownerCount(t, st, tenantB); n != 1 {
		t.Fatalf("healthy tenant owner count = %d, want 1", n)
	}
	if err := st.RequireLiveTenantService(ctx, tenantA); !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Fatalf("orphan tenant service admission = %v", err)
	}
	if err := projections.New(st).Rebuild(ctx, log); err != nil {
		t.Fatalf("old orphan source blocked rebuild: %v", err)
	}
}
