// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestServedIdentityPendingTerminalReadbackSurvivesProjectionGap(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	registerServedTenant(t, h, "Pending terminal identity readback")
	reader := seedScopedToken(t, h.store, h.tenant, "identities:read")
	owner, err := h.srv.orch.CreateOwner(t.Context(), h.tenant, "service", "terminal-readback", "")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := h.srv.orch.CreateIdentity(t.Context(), h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "terminal-readback.test", OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.orch.Transition(t.Context(), h.tenant, identity.ID, orchestrator.StateIssued, "initial issue"); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]string{
		"identity_id": identity.ID, "from": "issued", "to": "revoked", "reason": "cessationOfOperation",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.store.ClaimIdentityTerminalCommand(t.Context(), store.IdentityTerminalCommand{
		IdentityID: identity.ID, TargetState: "revoked",
		RequestBinding: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Event: events.Event{ID: uuid.NewString(), Type: projections.EventIdentityRevoked,
			TenantID: h.tenant, Time: time.Now().UTC().Truncate(time.Microsecond),
			SchemaVersion: events.DefaultSchemaVersion, Data: payload},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/identities/" + identity.ID, "/api/v1/identities"} {
		status, body := secretsReq(t, h, http.MethodGet, path, reader, nil)
		if status != http.StatusOK || !bytes.Contains(body, []byte(`"terminal_pending":true`)) ||
			!bytes.Contains(body, []byte(`"terminal_target_state":"revoked"`)) {
			t.Fatalf("%s concealed terminal denial: HTTP %d %s", path, status, body)
		}
	}
}

// A terminal identity event must stop a queued signing job even when the event
// was retained and its relational read model did not commit yet.
func TestIdentityRetainedRevocationRefusesQueuedSigning(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := t.Context()
	owner, err := h.orch.CreateOwner(ctx, h.tenant, "service", "terminal-gap", "")
	if err != nil {
		t.Fatal(err)
	}
	ident, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{Kind: store.KindX509Certificate, Name: "terminal-gap.served.test", OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateIssued, "initial issue"); err != nil {
		t.Fatal(err)
	}
	entry := pendingOutboxByDestination(t, h, "ca.issue")
	msg := orchestrator.Message{TenantID: h.tenant, Destination: "ca.issue", Payload: entry.Payload, IdempotencyKey: entry.IdempotencyKey}
	if _, err := h.store.SystemPool().Exec(ctx, `CREATE FUNCTION qa_identity_terminal_projection_fail() RETURNS trigger
		LANGUAGE plpgsql AS $$ BEGIN
			IF NEW.status = 'revoked' THEN RAISE EXCEPTION 'qa injected identity terminal projection outage'; END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER qa_identity_terminal_projection_fail BEFORE UPDATE ON identities
		FOR EACH ROW EXECUTE FUNCTION qa_identity_terminal_projection_fail()`); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	clearFault := func() {
		once.Do(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := h.store.SystemPool().Exec(cleanup, `DROP TRIGGER IF EXISTS qa_identity_terminal_projection_fail ON identities;
				DROP FUNCTION IF EXISTS qa_identity_terminal_projection_fail()`); err != nil {
				t.Errorf("clear owned projection fault: %v", err)
			}
		})
	}
	t.Cleanup(clearFault)
	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateRevoked, "cessationOfOperation"); err == nil {
		t.Fatal("revocation reported success despite failed SQL projection")
	} else {
		t.Logf("owned projection fault returned: %v", err)
	}
	retained := 0
	if err := h.log.Replay(ctx, 0, func(event events.Event) error {
		if event.TenantID == h.tenant && event.Type == projections.EventIdentityRevoked {
			retained++
		}
		return nil
	}); err != nil || retained != 1 {
		t.Fatalf("fault did not retain exactly one revoke: count=%d error=%v", retained, err)
	}
	if state, err := h.store.GetIdentity(ctx, h.tenant, ident.ID); err != nil || state.Status != string(orchestrator.StateIssued) {
		t.Fatalf("fault precondition: projected identity = %+v, %v; want issued", state, err)
	}
	before := len(dispatcherCertificates(t, h))
	if err := h.handler.Deliver(ctx, msg); err == nil {
		t.Fatal("retained identity revocation admitted a queued signing job")
	}
	if after := len(dispatcherCertificates(t, h)); after != before {
		t.Fatalf("terminal-gap signing recorded a certificate: %d -> %d", before, after)
	}
	clearFault()
	if healed, err := reconcilePendingIdentityTerminals(ctx, h.store, h.log); err != nil || healed != 1 {
		t.Fatalf("retained terminal recovery: healed=%d err=%v", healed, err)
	}
	if healed, err := reconcilePendingIdentityTerminals(ctx, h.store, h.log); err != nil || healed != 0 {
		t.Fatalf("repeated terminal recovery: healed=%d err=%v", healed, err)
	}
	if state, err := h.store.GetIdentity(ctx, h.tenant, ident.ID); err != nil || state.Status != string(orchestrator.StateRevoked) {
		t.Fatalf("reconciled terminal state = %+v, %v", state, err)
	}
	if err := h.handler.Deliver(ctx, msg); err == nil {
		t.Fatal("reconciled terminal identity admitted the queued signing job")
	}
	if err := projections.New(h.store).Rebuild(ctx, h.log); err != nil {
		t.Fatalf("cold lifecycle projection replay: %v", err)
	}
	if state, err := h.store.GetIdentity(ctx, h.tenant, ident.ID); err != nil || state.Status != string(orchestrator.StateRevoked) {
		t.Fatalf("cold terminal state = %+v, %v", state, err)
	}
}

func TestIdentityPreappendTerminalCommandRefusesSigningAndRecovers(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := t.Context()
	owner, err := h.orch.CreateOwner(ctx, h.tenant, "service", "preappend-terminal", "")
	if err != nil {
		t.Fatal(err)
	}
	ident, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{Kind: store.KindX509Certificate, Name: "preappend-terminal.served.test", OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateIssued, "initial issue"); err != nil {
		t.Fatal(err)
	}
	entry := pendingOutboxByDestination(t, h, "ca.issue")
	msg := orchestrator.Message{TenantID: h.tenant, Destination: "ca.issue", Payload: entry.Payload, IdempotencyKey: entry.IdempotencyKey}
	payload, err := json.Marshal(map[string]any{
		"identity_id": ident.ID, "from": "issued", "to": "revoked", "reason": "cessationOfOperation",
	})
	if err != nil {
		t.Fatal(err)
	}
	first := store.IdentityTerminalCommand{
		IdentityID: ident.ID, RequestBinding: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TargetState: "revoked", Event: events.Event{
			ID: uuid.NewString(), Type: projections.EventIdentityRevoked,
			TenantID: h.tenant, Time: time.Now().UTC().Truncate(time.Microsecond),
			SchemaVersion: events.DefaultSchemaVersion, Data: payload,
		},
	}
	claimed, err := h.store.ClaimIdentityTerminalCommand(ctx, first)
	if err != nil || claimed.Event.ID != first.Event.ID {
		t.Fatalf("first terminal claim = %+v, %v", claimed, err)
	}
	pendingTargets, err := h.store.PendingIdentityTerminalTargets(ctx, h.tenant, []string{ident.ID})
	if err != nil || pendingTargets[ident.ID] != "revoked" {
		t.Fatalf("operator pending-terminal readback = %+v, %v", pendingTargets, err)
	}
	if _, found, err := h.log.EventByID(ctx, first.Event.ID); err != nil || found {
		t.Fatalf("preappend fixture already has event: found=%t err=%v", found, err)
	}
	if err := h.handler.Deliver(ctx, msg); err == nil || len(dispatcherCertificates(t, h)) != 0 {
		t.Fatalf("preappend command admitted signing: %v", err)
	}
	other := first
	other.RequestBinding = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := h.store.ClaimIdentityTerminalCommand(ctx, other); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("different first writer displaced terminal command: %v", err)
	}
	if healed, err := reconcilePendingIdentityTerminals(ctx, h.store, h.log); err != nil || healed != 1 {
		t.Fatalf("preappend recovery = %d, %v", healed, err)
	}
	if state, err := h.store.GetIdentity(ctx, h.tenant, ident.ID); err != nil || state.Status != "revoked" {
		t.Fatalf("recovered terminal state = %+v, %v", state, err)
	}
}
