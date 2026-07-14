// SPDX-License-Identifier: MPL-2.0

package projections_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestCertificateProjectionRejectsIDReuseAsDomainCorruption distinguishes a
// legitimate at-least-once replay from a corrupt event that reuses one UUID for
// different certificate bytes. The sink must return a stable domain error; a raw
// certificates_pkey error is both opaque and indistinguishable from the live
// inline/tail race above.
func TestCertificateProjectionRejectsIDReuseAsDomainCorruption(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	proj := projections.New(s)
	const certID = "10000000-0000-4000-8000-000000000098"
	first := projectorEvent(t, projections.EventCertificateRecorded, projections.CertificateRecorded{
		ID: certID, Subject: "CN=first.example", Fingerprint: "sha256:first", Serial: "98",
	})
	if err := proj.Apply(ctx, first); err != nil {
		t.Fatalf("first certificate: %v", err)
	}
	corrupt := projectorEvent(t, projections.EventCertificateRecorded, projections.CertificateRecorded{
		ID: certID, Subject: "CN=different.example", Fingerprint: "sha256:different", Serial: "99",
	})
	err := proj.Apply(ctx, corrupt)
	if err == nil || !strings.Contains(err.Error(), "reuses id") || strings.Contains(err.Error(), "certificates_pkey") {
		t.Fatalf("corrupt certificate id reuse error = %v, want stable domain error without raw SQL constraint", err)
	}
}

// TestConnectorReceiptProjectionConvergesByOutbox pins the second natural key
// on connector evidence. A retry may carry a fresh receipt UUID, but one outbox
// command still has one canonical receipt whose latest status wins.
func TestConnectorReceiptProjectionConvergesByOutbox(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	proj := projections.New(s)
	outboxID := int64(42)
	for _, candidate := range []projections.ConnectorDeliveryRecorded{
		{ID: "10000000-0000-4000-8000-000000000096", OutboxID: &outboxID, Destination: "connector.deploy", Connector: "nginx", Target: "edge", Status: "failed", Attempts: 1},
		{ID: "10000000-0000-4000-8000-000000000097", OutboxID: &outboxID, Destination: "connector.deploy", Connector: "nginx", Target: "edge", Status: "delivered", Attempts: 2},
	} {
		if err := proj.Apply(ctx, projectorEvent(t, projections.EventConnectorDeliveryRecorded, candidate)); err != nil {
			t.Fatalf("apply connector receipt %s: %v", candidate.Status, err)
		}
	}
	receipts, err := s.ListConnectorDeliveryReceiptsPage(ctx, tenantA, "", store.ZeroUUID, 10)
	if err != nil {
		t.Fatalf("list connector receipts: %v", err)
	}
	if len(receipts) != 1 || receipts[0].Status != "delivered" || receipts[0].Attempts != 2 {
		t.Fatalf("connector receipts = %+v, want one converged delivered receipt", receipts)
	}
}

// TestCertificateProjectionConvergesWithInlineTailRace reproduces the served
// at-least-once race: the event is visible in JetStream while the inline SQL
// projection is still committing, so the durable tail can try the same insert
// concurrently. Either writer may discover the id or fingerprint uniqueness
// conflict first; both must converge to the same one-row inventory.
func TestCertificateProjectionConvergesWithInlineTailRace(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	const certID = "10000000-0000-4000-8000-000000000099"
	event := projectorEvent(t, projections.EventCertificateRecorded, projections.CertificateRecorded{
		ID: certID, Subject: "CN=race.example", SANs: []string{"race.example"},
		Fingerprint: "sha256:projection-race", Serial: "99", Source: "issued",
	})
	cert := store.Certificate{
		ID: certID, TenantID: tenantA, Subject: "CN=race.example", SANs: []string{"race.example"},
		Fingerprint: "sha256:projection-race", Serial: "99", Source: "issued", CreatedAt: event.Time,
	}

	rowInserted := make(chan struct{})
	releaseCommit := make(chan struct{})
	inlineDone := make(chan error, 1)
	go func() {
		inlineDone <- s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
			if err := s.ApplyCertificateRecordedTx(ctx, tx, cert); err != nil {
				return err
			}
			close(rowInserted)
			<-releaseCommit
			return nil
		})
	}()
	select {
	case <-rowInserted:
	case err := <-inlineDone:
		t.Fatalf("inline projection insert: %v", err)
	}

	tailDone := make(chan error, 1)
	go func() { tailDone <- projections.New(s).Apply(ctx, event) }()
	select {
	case err := <-tailDone:
		close(releaseCommit)
		t.Fatalf("tail projection returned before the inline uniqueness lock committed: %v", err)
	case <-time.After(100 * time.Millisecond):
		// The second transaction is waiting on the first transaction's unique row.
	}
	close(releaseCommit)
	if err := <-inlineDone; err != nil {
		t.Fatalf("inline projection commit: %v", err)
	}
	if err := <-tailDone; err != nil {
		t.Fatalf("tail projection after inline commit: %v", err)
	}

	items, err := s.ListCertificatesPage(ctx, tenantA, store.ZeroUUID, nil, 10, nil)
	if err != nil {
		t.Fatalf("list certificates: %v", err)
	}
	if len(items) != 1 || items[0].ID != certID || items[0].Fingerprint != cert.Fingerprint {
		t.Fatalf("racing projections = %+v, want one canonical certificate", items)
	}
}

// TestProjectorCreateEventsAreReplayIdempotentWithTenantCompositeKeys pins the
// live-writer contract used by the API's inline projector and the durable tailer:
// applying the same source event again must converge to one read-model row, not
// surface a duplicate-key error on the tenant-composite key (tenant_id, id).
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

// TestCORRECT003CreateProjectionIDsAreTenantScoped proves the schema matches the
// projector's tenant-composite conflict target. The read-model identity is
// (tenant_id, id); a single-column id primary key makes the second tenant fail
// with owners_pkey before compose can prove the served lifecycle.
func TestCORRECT003CreateProjectionIDsAreTenantScoped(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for _, tenant := range []struct{ id, name string }{{tenantA, "Acme"}, {tenantB, "Beta"}} {
		if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenant.id, Name: tenant.name}); err != nil {
			t.Fatalf("seed tenant %s: %v", tenant.id, err)
		}
	}
	proj := projections.New(s)

	const (
		ownerID  = "10000000-0000-4000-8000-000000000201"
		issuerID = "10000000-0000-4000-8000-000000000202"
		identID  = "10000000-0000-4000-8000-000000000203"
	)
	issuerPtr := issuerID
	for _, tenantID := range []string{tenantA, tenantB} {
		if err := proj.Apply(ctx, projectorEventForTenant(t, tenantID, projections.EventOwnerCreated, projections.OwnerCreated{
			ID: ownerID, Kind: "workload", Name: "shared-id-owner",
		})); err != nil {
			t.Fatalf("apply owner.created for tenant %s: %v", tenantID, err)
		}
		if err := proj.Apply(ctx, projectorEventForTenant(t, tenantID, projections.EventIssuerCreated, projections.IssuerCreated{
			ID: issuerID, Kind: "x509_ca", Name: "shared-id-ca",
			Chain: []string{"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"},
		})); err != nil {
			t.Fatalf("apply issuer.created for tenant %s: %v", tenantID, err)
		}
		if err := proj.Apply(ctx, projectorEventForTenant(t, tenantID, projections.EventIdentityCreated, projections.IdentityCreated{
			ID: identID, Kind: "x509_certificate", Name: "shared-id.example",
			OwnerID: ownerID, IssuerID: &issuerPtr, Attributes: json.RawMessage(`{}`),
		})); err != nil {
			t.Fatalf("apply identity.created for tenant %s: %v", tenantID, err)
		}
	}

	for _, tenantID := range []string{tenantA, tenantB} {
		owners, err := s.ListOwners(ctx, tenantID)
		if err != nil {
			t.Fatalf("list owners for tenant %s: %v", tenantID, err)
		}
		issuers, err := s.ListIssuers(ctx, tenantID)
		if err != nil {
			t.Fatalf("list issuers for tenant %s: %v", tenantID, err)
		}
		identities, err := s.ListIdentities(ctx, tenantID)
		if err != nil {
			t.Fatalf("list identities for tenant %s: %v", tenantID, err)
		}
		if len(owners) != 1 || len(issuers) != 1 || len(identities) != 1 {
			t.Fatalf("tenant %s read model counts = owners:%d issuers:%d identities:%d, want 1/1/1",
				tenantID, len(owners), len(issuers), len(identities))
		}
	}
}

func projectorEvent(t *testing.T, eventType string, payload any) events.Event {
	return projectorEventForTenant(t, tenantA, eventType, payload)
}

func projectorEventForTenant(t *testing.T, tenantID, eventType string, payload any) events.Event {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal %s: %v", eventType, err)
	}
	return events.Event{Type: eventType, TenantID: tenantID, Time: time.Now().UTC(), Data: data}
}
