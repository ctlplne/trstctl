// SPDX-License-Identifier: BUSL-1.1

package retirement

import (
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/decommission/depstate"
	"trstctl.com/trstctl/internal/events"
)

func TestRetirementLaterRegistrationIndexedAcrossColdRestart(t *testing.T) {
	ctx := t.Context()
	const tenant = "a1000000-0000-4000-8000-000000000001"
	const otherTenant = "b2000000-0000-4000-8000-000000000002"
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := events.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := log.Close(); err != nil {
			t.Error(err)
		}
	}()
	appendRegistration := func(tenantID, keyID, dependentID string) events.Event {
		t.Helper()
		ev, err := depstate.Encode(depstate.DependencyRegisteredV1{
			TenantID: tenantID, KeyID: keyID,
			Dependent: depstate.Dependent{Class: depstate.DependentCredential, ID: dependentID},
		})
		if err != nil {
			t.Fatal(err)
		}
		stored, err := log.Append(ctx, ev)
		if err != nil {
			t.Fatal(err)
		}
		return stored
	}
	first := appendRegistration(tenant, "key-a", "leaf-before")
	if _, err := log.Append(ctx, events.Event{TenantID: otherTenant, Type: "unrelated.event", Data: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	frozen, err := log.Append(ctx, events.Event{TenantID: tenant, Type: "audit.other", Data: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	appendRegistration(otherTenant, "key-a", "cross-tenant")
	appendRegistration(tenant, "key-b", "different-key")
	requested := RequestedV1{TenantID: tenant, KeyID: "key-a", LedgerPosition: frozen.Sequence}
	h := &Handler{log: log}
	before, later, err := h.replayEvidence(ctx, requested)
	if err != nil || later || len(before) != 2 || before[0].Sequence != first.Sequence || before[1].Sequence != frozen.Sequence {
		t.Fatalf("frozen segment or unrelated later registration changed: facts=%+v later=%v err=%v", before, later, err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	log, err = events.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.log = log
	before, later, err = h.replayEvidence(ctx, requested)
	if err != nil || later || len(before) != 2 {
		t.Fatalf("cold frozen segment or unrelated registration changed: count=%d later=%v err=%v", len(before), later, err)
	}
	appendRegistration(tenant, "key-a", "leaf-after")
	before, later, err = h.replayEvidence(ctx, requested)
	if err != nil || !later || len(before) != 2 {
		t.Fatalf("later dependent was not refused after cold replay: count=%d later=%v err=%v", len(before), later, err)
	}
	if _, err := log.Append(ctx, events.Event{TenantID: tenant, Type: depstate.TypeDependencyRegistered,
		Data: []byte(`{"tenant_id":`)}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.replayEvidence(ctx, requested); err == nil {
		t.Fatal("malformed retained registration was ignored by the retirement worker")
	}
}
