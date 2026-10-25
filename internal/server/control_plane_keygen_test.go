// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Owner decision 2026-10-24: work queued before a tenant turned control-plane
// key generation off is refused when it reaches the mint, before any key is
// generated. The refusal is a definite no-effect, so the job retries and
// completes once the tenant turns key generation back on. This harness's
// orchestrator has no first-issuance guard, which stands in for work queued
// while the tenant still allowed it.
func TestQueuedControlPlaneKeygenIsRefusedAtTheMintWhileOff(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := t.Context()
	setKeygen := func(enabled bool) {
		t.Helper()
		operator := events.ContextWithActor(ctx, events.Actor{Subject: "ops@example.test"})
		if _, err := h.orch.SetControlPlaneKeygen(operator, h.tenant, projections.ControlPlaneKeygenSet{
			Enabled: enabled, Source: store.ControlPlaneKeygenSourceOperator, Reason: "mint-time check", SetBy: "ops@example.test",
		}); err != nil {
			t.Fatal(err)
		}
	}
	owner, err := h.orch.CreateOwner(ctx, h.tenant, "service", "keygen-off", "")
	if err != nil {
		t.Fatal(err)
	}
	ident, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{Kind: store.KindX509Certificate, Name: "keygen-off.example.test", OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateIssued, "queued before the switch"); err != nil {
		t.Fatal(err)
	}
	setKeygen(false)
	pending := pendingOutboxByDestination(t, h, "ca.issue")
	message := orchestrator.Message{ID: pending.ID, TenantID: h.tenant, Destination: pending.Destination, Payload: pending.Payload, IdempotencyKey: pending.IdempotencyKey}
	err = h.handler.Deliver(ctx, message)
	if !errors.Is(err, orchestrator.ErrControlPlaneKeygenOff) || !orchestrator.IsDefiniteNoEffect(err) {
		t.Fatalf("mint with the switch off = %v, want a definite no-effect refusal naming the switch", err)
	}
	if certs := dispatcherCertificates(t, h); len(certs) != 0 {
		t.Fatalf("the refused mint recorded %d certificates", len(certs))
	}
	if n := eventCount(t, h.log, h.tenant, "issuance.server_side_keygen"); n != 0 {
		t.Fatalf("the refused mint recorded %d server-side keygen events, but generated no key", n)
	}
	setKeygen(true)
	if err := h.handler.Deliver(ctx, message); err != nil {
		t.Fatalf("mint after the switch is back on: %v", err)
	}
	if certs := dispatcherCertificates(t, h); len(certs) != 1 {
		t.Fatalf("the retried mint recorded %d certificates, want 1", len(certs))
	}
}

// The renewal of an identity whose key the control plane generated is the
// other path the switch governs: with it off, the renewal mint is refused the
// same way and no successor is recorded.
func TestControlPlaneKeyRenewalIsRefusedWhileOff(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := t.Context()
	owner, err := h.orch.CreateOwner(ctx, h.tenant, "service", "keygen-renewal", "")
	if err != nil {
		t.Fatal(err)
	}
	ident, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{Kind: store.KindX509Certificate, Name: "keygen-renewal.example.test", OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateIssued, "control-plane key"); err != nil {
		t.Fatal(err)
	}
	dispatchOutbox(t, h, 1)
	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateDeployed, "deployed"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.orch.SetControlPlaneKeygen(ctx, h.tenant, projections.ControlPlaneKeygenSet{
		Enabled: false, Source: store.ControlPlaneKeygenSourceOperator, Reason: "every workload brings a CSR now", SetBy: "ops@example.test",
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.orch.TransitionWithIdempotency(ctx, h.tenant, ident.ID, orchestrator.StateRenewing, "renewal while off", "renew-while-off"); err != nil {
		t.Fatal(err)
	}
	pending := pendingOutboxByDestination(t, h, "ca.renew")
	message := orchestrator.Message{ID: pending.ID, TenantID: h.tenant, Destination: pending.Destination, Payload: pending.Payload, IdempotencyKey: pending.IdempotencyKey}
	err = h.handler.Deliver(ctx, message)
	if !errors.Is(err, orchestrator.ErrControlPlaneKeygenOff) {
		t.Fatalf("control-plane key renewal with the switch off = %v, want the switch's refusal", err)
	}
	if certs := dispatcherCertificates(t, h); len(certs) != 1 {
		t.Fatalf("the refused renewal left %d certificates, want only the original", len(certs))
	}
}
