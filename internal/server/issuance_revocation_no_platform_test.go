// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// An external-only customer's completed revocation must release its outbox
// lifetime. Publishing an unrelated platform CRL cannot keep the customer busy.
func TestExternalOnlyRevocationCompletesWithoutPlatformCRL(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := t.Context()
	owner, err := h.orch.CreateOwner(ctx, h.tenant, "service", "external-only owner", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "external-only.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.orch.Transition(ctx, h.tenant, identity.ID, orchestrator.StateIssued, "external issuance intent"); err != nil {
		t.Fatal(err)
	}
	certificate := recordRevocationTestLeaf(t, h, owner.ID, identity.Name, "selected-ca", "no-platform-crl", "")
	if _, err := h.orch.RecordConnectorDelivery(ctx, h.tenant, store.ConnectorDeliveryReceipt{
		IdentityID: &identity.ID, Destination: "connector.deploy", Connector: "nginx", Target: "external-only",
		Fingerprint: certificate.Fingerprint, Status: "verified", IdempotencyKey: "external-only-deployed",
	}); err != nil {
		t.Fatal(err)
	}
	revocations, publications := 0, 0
	upstream := revocationTestCA{revoke: func(_ context.Context, request ca.RevokeRequest) error {
		if request.TenantID != h.tenant || request.Serial != certificate.Serial || request.ReasonCode != 1 {
			t.Fatal("upstream lost the exact tenant, certificate or reason")
		}
		revocations++
		return nil
	}}
	srv := &Server{orch: h.orch, outbox: h.outbox}
	_, err = srv.buildExternalCAService(Deps{Store: h.store, Log: h.log, ExternalCAs: []ExternalCA{{
		ID: "selected-ca", Type: "vaultpki", Name: "selected authority",
		Factory: func(context.Context) (ca.CA, func(), error) { return upstream, func() {}, nil },
	}}}, h.handler.idem)
	if err != nil {
		t.Fatal(err)
	}
	h.handler.externalCAs = srv.externalCAs
	h.handler.publishCRL = func(context.Context, string) error {
		publications++
		return errNoCRLSurface
	}
	if issued, err := h.store.HasIssuedCerts(ctx, h.tenant, IssuingCAID()); err != nil || issued {
		t.Fatalf("fixture unexpectedly has platform-issued certificates: issued=%v error=%v", issued, err)
	}
	if err := h.orch.Transition(ctx, h.tenant, identity.ID, orchestrator.StateRevoked, "keyCompromise"); err != nil {
		t.Fatal(err)
	}
	row := pendingOutboxByDestination(t, h, "revocation.publish")
	did, err := h.outbox.DispatchOneScoped(ctx, h.handler, orchestrator.DestinationScope{IncludePrefixes: []string{"revocation.publish"}})
	if err != nil || !did {
		t.Fatalf("dispatch: did=%v error=%v", did, err)
	}
	var status string
	var holds int
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status, cardinality(receiver_pending_ids) FROM outbox WHERE tenant_id=$1 AND id=$2`, h.tenant, row.ID).Scan(&status, &holds)
	}); err != nil {
		t.Fatal(err)
	}
	if status != "delivered" || holds != 0 || publications != 0 || revocations != 1 {
		t.Fatalf("completed external revocation must not require a platform CRL: status=%s holds=%d platform_publications=%d upstream_revocations=%d", status, holds, publications, revocations)
	}
	if err := h.store.RequireTenantAgentWorkQuiescent(ctx, h.tenant); err != nil {
		t.Fatalf("completed external revocation prevents customer suspension: %v", err)
	}
	got, err := h.store.GetCertificate(ctx, h.tenant, certificate.ID)
	if err != nil || got.Status != "revoked" {
		t.Fatalf("upstream-confirmed certificate: status=%s error=%v", got.Status, err)
	}
	message := orchestrator.Message{ID: row.ID, TenantID: h.tenant, Destination: row.Destination, Payload: row.Payload, IdempotencyKey: row.IdempotencyKey}
	if err := h.handler.Deliver(ctx, message); err != nil {
		t.Fatal(err)
	}
	if revocations != 1 || publications != 0 {
		t.Fatalf("cached retry repeated work: upstream=%d platform=%d", revocations, publications)
	}
}
