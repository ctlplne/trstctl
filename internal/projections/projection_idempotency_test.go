package projections_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"trustctl.io/trustctl/internal/events"
	"trustctl.io/trustctl/internal/projections"
	"trustctl.io/trustctl/internal/store"
)

// TestProjectorCreateEventsAreReplayIdempotentWithTenantCompositeKeys pins the
// live-writer contract used by the API's inline projector and the durable tailer:
// applying the same source event again must converge to one read-model row, not
// surface a duplicate-key error on the tenant-composite UNIQUE (tenant_id, id).
func TestProjectorCreateEventsAreReplayIdempotentWithTenantCompositeKeys(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	proj := projections.New(s)

	const (
		ownerID  = "10000000-0000-4000-8000-000000000001"
		issuerID = "10000000-0000-4000-8000-000000000002"
		identID  = "10000000-0000-4000-8000-000000000003"
	)
	issuerPtr := issuerID
	eventsToReplay := []events.Event{
		projectorEvent(t, projections.EventOwnerCreated, projections.OwnerCreated{
			ID: ownerID, Kind: "workload", Name: "payments",
		}),
		projectorEvent(t, projections.EventIssuerCreated, projections.IssuerCreated{
			ID: issuerID, Kind: "x509_ca", Name: "e2e-ca",
			Chain: []string{"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"},
		}),
		projectorEvent(t, projections.EventIdentityCreated, projections.IdentityCreated{
			ID: identID, Kind: "x509_certificate", Name: "payments.example",
			OwnerID: ownerID, IssuerID: &issuerPtr, Attributes: json.RawMessage(`{}`),
		}),
	}

	for _, ev := range eventsToReplay {
		if err := proj.Apply(ctx, ev); err != nil {
			t.Fatalf("first apply %s: %v", ev.Type, err)
		}
		if err := proj.Apply(ctx, ev); err != nil {
			t.Fatalf("replay apply %s: %v", ev.Type, err)
		}
	}

	owners, err := s.ListOwners(ctx, tenantA)
	if err != nil {
		t.Fatalf("list owners: %v", err)
	}
	issuers, err := s.ListIssuers(ctx, tenantA)
	if err != nil {
		t.Fatalf("list issuers: %v", err)
	}
	identities, err := s.ListIdentities(ctx, tenantA)
	if err != nil {
		t.Fatalf("list identities: %v", err)
	}
	if len(owners) != 1 || len(issuers) != 1 || len(identities) != 1 {
		t.Fatalf("replayed read model counts = owners:%d issuers:%d identities:%d, want 1/1/1",
			len(owners), len(issuers), len(identities))
	}
}

func projectorEvent(t *testing.T, eventType string, payload any) events.Event {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal %s: %v", eventType, err)
	}
	return events.Event{Type: eventType, TenantID: tenantA, Time: time.Now().UTC(), Data: data}
}
