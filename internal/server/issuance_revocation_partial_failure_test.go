// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// A CA may refuse an expired predecessor while still accepting the live leaf.
// One member's refusal must not leave every later member trusted. Keep the
// failed command retryable and never invent a revocation receipt for it.
func TestIdentityRevocationContinuesAfterPredecessorRefusal(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := t.Context()
	owner, err := h.orch.CreateOwner(ctx, h.tenant, "service", "partial revocation", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "partial-revoke.example.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.orch.Transition(ctx, h.tenant, identity.ID, orchestrator.StateIssued, "issue"); err != nil {
		t.Fatal(err)
	}
	first := recordRevocationTestLeaf(t, h, owner.ID, identity.Name, "selected-ca", "refused-first", "")
	current := recordRevocationTestLeaf(t, h, owner.ID, identity.Name, "selected-ca", "accepted-current", first.ID)
	for _, certificate := range []store.Certificate{first, current} {
		if _, err := h.orch.RecordConnectorDelivery(ctx, h.tenant, store.ConnectorDeliveryReceipt{
			IdentityID: &identity.ID, Destination: "connector.deploy", Connector: "nginx", Target: "qa",
			Fingerprint: certificate.Fingerprint, Status: "verified", IdempotencyKey: "deploy:" + certificate.ID,
		}); err != nil {
			t.Fatal(err)
		}
	}
	refuseFirst := true
	calls := map[string]int{}
	upstream := revocationTestCA{revoke: func(_ context.Context, request ca.RevokeRequest) error {
		if request.TenantID != h.tenant || request.ReasonCode != 1 {
			t.Fatal("revocation lost tenant or reason")
		}
		calls[request.Serial]++
		if request.Serial == first.Serial && refuseFirst {
			return errors.New("issuing authority did not confirm revocation")
		}
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
	if err := h.orch.Transition(ctx, h.tenant, identity.ID, orchestrator.StateRevoked, "keyCompromise"); err != nil {
		t.Fatal(err)
	}
	row := pendingOutboxByDestination(t, h, "revocation.publish")
	message := orchestrator.Message{ID: row.ID, TenantID: h.tenant, Destination: row.Destination, Payload: row.Payload, IdempotencyKey: row.IdempotencyKey}
	for attempt := 1; attempt <= 2; attempt++ {
		if err := h.handler.Deliver(ctx, message); err == nil {
			t.Fatal("partial refusal was reported as completed revocation")
		}
		gotFirst, err := h.store.GetCertificate(ctx, h.tenant, first.ID)
		if err != nil {
			t.Fatal(err)
		}
		gotCurrent, err := h.store.GetCertificate(ctx, h.tenant, current.ID)
		if err != nil {
			t.Fatal(err)
		}
		if gotFirst.Status == "revoked" || gotFirst.RevokedAt != nil {
			t.Fatal("refused predecessor received a false revocation receipt")
		}
		if gotCurrent.Status != "revoked" || gotCurrent.RevocationReason != "keyCompromise" {
			t.Fatalf("predecessor refusal starved the current certificate: status=%s calls=%v", gotCurrent.Status, calls)
		}
		if calls[first.Serial] != attempt || calls[current.Serial] != 1 {
			t.Fatalf("retry lost failure or repeated confirmed revocation: %v", calls)
		}
	}
	refuseFirst = false
	if err := h.handler.Deliver(ctx, message); err != nil {
		t.Fatal(err)
	}
	if err := h.handler.Deliver(ctx, message); err != nil {
		t.Fatal(err)
	}
	if calls[first.Serial] != 3 || calls[current.Serial] != 1 {
		t.Fatalf("completed retry repeated upstream work: %v", calls)
	}
}
