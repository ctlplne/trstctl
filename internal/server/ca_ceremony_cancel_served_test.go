// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestServedCACeremonyCancelIsTerminalAndAudited(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	opener := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "ceremony-opener", []string{"issuers:write", "issuers:read"})
	approver := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "distinct-custodian", []string{"issuers:write", "issuers:read"})
	readOnly := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "reader", []string{"issuers:read"})
	spec := map[string]any{"common_name": "cancelled root", "ttl_seconds": 31536000, "signature_algorithm": "ECDSA-P256"}
	ceremony := createCACeremony(t, h, opener, "create_root", "", spec, 2, "cancelled-root-ceremony")
	if ceremony.Status != "pending" || ceremony.Approvals != 0 {
		t.Fatalf("initial ceremony = %+v", ceremony)
	}
	path := "/api/v1/ca/ceremonies/" + ceremony.ID + "/cancel"
	if code, _ := doBearer(t, h.ts, http.MethodPost, path, readOnly, "readonly-cancel", map[string]any{"reason": "change window closed"}); code != http.StatusForbidden {
		t.Fatalf("read-only cancel = %d, want 403", code)
	}
	if code, _ := doBearer(t, h.ts, http.MethodPost, path, opener, "blank-reason-cancel", map[string]any{"reason": " "}); code != http.StatusUnprocessableEntity {
		t.Fatalf("blank-reason cancel = %d, want 422", code)
	}
	code, body := doBearer(t, h.ts, http.MethodPost, path, opener, "exact-cancel", map[string]any{"reason": "change window closed"})
	if code != http.StatusOK {
		t.Fatalf("cancel = %d body=%s, want 200", code, body)
	}
	var closed struct {
		Status string `json:"status"`
		ID     string `json:"id"`
	}
	if err := json.Unmarshal(body, &closed); err != nil || closed.ID != ceremony.ID || closed.Status != "cancelled" {
		t.Fatalf("cancel response = %+v, %v", closed, err)
	}
	code, body = doBearer(t, h.ts, http.MethodPost, path, opener, "exact-cancel", map[string]any{"reason": "change window closed"})
	if code != http.StatusOK || !strings.Contains(string(body), `"status":"cancelled"`) {
		t.Fatalf("same-key replay = %d body=%s", code, body)
	}
	if n := servedEventCount(t, h, "ca.ceremony.cancelled"); n != 1 {
		t.Fatalf("cancel events = %d, want exactly 1", n)
	}
	if code, _ := doBearer(t, h.ts, http.MethodPost, path, opener, "different-cancel", map[string]any{"reason": "change window closed"}); code != http.StatusConflict {
		t.Fatalf("different-key cancel of terminal ceremony = %d, want 409", code)
	}
	if code, _ := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/"+ceremony.ID+"/approvals", approver, "approve-cancelled", map[string]any{}); code != http.StatusConflict {
		t.Fatalf("approval after cancel = %d, want 409", code)
	}
	if code, _ := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/roots", opener, "create-cancelled-root", map[string]any{"ceremony_id": ceremony.ID, "spec": spec}); code != http.StatusConflict {
		t.Fatalf("root creation after cancel = %d, want 409", code)
	}
	readback, err := h.store.GetKeyCeremony(context.Background(), h.tenant, ceremony.ID)
	if err != nil || readback.Status != "cancelled" || readback.Approvals != 0 {
		t.Fatalf("terminal readback = %+v, %v", readback, err)
	}
	if _, err := h.store.GetKeyCeremony(context.Background(), "00000000-0000-4000-8000-000000000999", ceremony.ID); err == nil || err == store.ErrKeyCeremonyNotPending {
		t.Fatalf("cross-tenant ceremony read leaked: %v", err)
	}
}

func TestServedCACeremonyUnpublishedCancelCommandRecoversOnce(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	opener := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "unpublished-cancel-opener", []string{"issuers:write", "issuers:read"})
	approver := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "unpublished-cancel-custodian", []string{"issuers:write", "issuers:read"})
	ceremony := createCACeremony(t, h, opener, "create_root", "", map[string]any{
		"common_name": "unpublished-cancel-root", "ttl_seconds": 31536000, "signature_algorithm": "ECDSA-P256",
	}, 1, "unpublished-cancel-start")
	payload, err := json.Marshal(projections.CACeremonyCancelled{
		CeremonyID: ceremony.ID, Actor: "unpublished-cancel-opener", Reason: "change window closed",
	})
	if err != nil {
		t.Fatal(err)
	}
	actor := events.Actor{Subject: "unpublished-cancel-opener"}
	command, created, err := h.store.ClaimCACeremonyCancelCommand(context.Background(), store.CACeremonyCancelCommand{
		TenantID: h.tenant, CeremonyID: ceremony.ID,
		Event: events.Event{ID: uuid.NewString(), Time: time.Now().UTC().Truncate(time.Microsecond),
			TenantID: h.tenant, Type: projections.EventCACeremonyCancelled,
			SchemaVersion: events.DefaultSchemaVersion, Data: payload, Actor: &actor},
	})
	if err != nil || !created {
		t.Fatalf("pre-append claim = %+v created=%t err=%v", command, created, err)
	}
	retry, created, err := h.store.ClaimCACeremonyCancelCommand(context.Background(), store.CACeremonyCancelCommand{
		TenantID: h.tenant, CeremonyID: ceremony.ID,
		Event: events.Event{ID: uuid.NewString(), Time: time.Now().UTC().Truncate(time.Microsecond),
			TenantID: h.tenant, Type: projections.EventCACeremonyCancelled,
			SchemaVersion: events.DefaultSchemaVersion, Data: payload, Actor: &actor},
	})
	if err != nil || created || retry.Event.ID != command.Event.ID {
		t.Fatalf("ambiguous-result retry replaced first command: %+v created=%t err=%v", retry, created, err)
	}
	if n := servedEventCount(t, h, projections.EventCACeremonyCancelled); n != 0 {
		t.Fatalf("pre-append cancel source count = %d", n)
	}
	path := "/api/v1/ca/ceremonies/" + ceremony.ID
	if code, body := doBearer(t, h.ts, http.MethodPost, path+"/approvals", approver,
		"unpublished-late-approval", map[string]any{}); code != http.StatusConflict {
		t.Fatalf("pre-append fence admitted approval = %d body=%s", code, body)
	}
	if healed, err := reconcilePendingCACeremonyCancels(context.Background(), h.store, h.log); err != nil || healed != 1 {
		t.Fatalf("pre-append recovery = %d, %v", healed, err)
	}
	if n := servedEventCount(t, h, projections.EventCACeremonyCancelled); n != 1 {
		t.Fatalf("recovered cancel source count = %d", n)
	}
	if code, body := doBearer(t, h.ts, http.MethodGet, path, opener, "", nil); code != http.StatusOK ||
		!strings.Contains(string(body), `"status":"cancelled"`) {
		t.Fatalf("recovered ceremony = %d body=%s", code, body)
	}
}

func TestServedCACeremonyRetainedCancelRefusesApprovalAndSigning(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	opener := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "cancel-gap-opener", []string{"issuers:write", "issuers:read"})
	custodian := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "cancel-gap-custodian", []string{"issuers:write", "issuers:read"})
	lateCustodian := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "cancel-gap-late-custodian", []string{"issuers:write", "issuers:read"})
	spec := map[string]any{"common_name": "cancel-gap-root", "ttl_seconds": 31536000, "signature_algorithm": "ECDSA-P256"}
	ceremony := createCACeremony(t, h, opener, "create_root", "", spec, 1, "cancel-gap-ceremony")
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/ceremonies/"+ceremony.ID+"/approvals", custodian,
		"cancel-gap-approval", map[string]any{}); code != http.StatusOK {
		t.Fatalf("pre-cancel approval = %d body=%s", code, body)
	}
	ctx := context.Background()
	if _, err := h.store.SystemPool().Exec(ctx, `CREATE FUNCTION qa_reject_cancel_projection() RETURNS trigger
	    LANGUAGE plpgsql AS $$ BEGIN
	      IF NEW.status = 'cancelled' THEN RAISE EXCEPTION 'qa injected cancel projection outage'; END IF;
	      RETURN NEW;
	    END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.SystemPool().Exec(ctx, `CREATE TRIGGER qa_reject_cancel_projection
	    BEFORE UPDATE ON ca_key_ceremonies FOR EACH ROW EXECUTE FUNCTION qa_reject_cancel_projection()`); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/ca/ceremonies/" + ceremony.ID
	if code, _ := doBearer(t, h.ts, http.MethodPost, path+"/cancel", opener, "cancel-gap-first",
		map[string]any{"reason": "operator stopped the ceremony"}); code == http.StatusOK {
		t.Fatal("cancel reported success while its SQL projection was blocked")
	}
	if n := servedEventCount(t, h, "ca.ceremony.cancelled"); n != 1 {
		t.Fatalf("retained cancel events = %d, want 1", n)
	}
	readback, err := h.store.GetKeyCeremony(ctx, h.tenant, ceremony.ID)
	if err != nil || readback.Status != "pending" {
		t.Fatalf("fault precondition: SQL ceremony = %+v err=%v, want pending", readback, err)
	}
	if code, body := doBearer(t, h.ts, http.MethodGet, path, opener, "", nil); code != http.StatusOK ||
		!strings.Contains(string(body), `"status":"cancellation_pending"`) {
		t.Fatalf("fenced operator readback = %d body=%s", code, body)
	}
	if code, body := doBearer(t, h.ts, http.MethodPost, path+"/approvals", lateCustodian,
		"cancel-gap-new-approval", map[string]any{}); code != http.StatusConflict {
		t.Fatalf("retained cancel admitted another approval = %d body=%s", code, body)
	}
	if code, body := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/roots", opener,
		"cancel-gap-root-sign", map[string]any{"ceremony_id": ceremony.ID, "spec": spec}); code != http.StatusConflict {
		t.Fatalf("retained cancel admitted root signing = %d body=%s", code, body)
	}
	if _, err := h.store.SystemPool().Exec(ctx, `DROP TRIGGER qa_reject_cancel_projection ON ca_key_ceremonies`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.SystemPool().Exec(ctx, `DROP FUNCTION qa_reject_cancel_projection()`); err != nil {
		t.Fatal(err)
	}
	if healed, err := reconcilePendingCACeremonyCancels(ctx, h.store, h.log); err != nil || healed != 1 {
		t.Fatalf("cancellation recovery = %d, %v; want one exact command", healed, err)
	}
	if n := servedEventCount(t, h, "ca.ceremony.cancelled"); n != 1 {
		t.Fatalf("recovered cancel events = %d, want original single event", n)
	}
	if code, body := doBearer(t, h.ts, http.MethodGet, path, opener, "", nil); code != http.StatusOK ||
		!strings.Contains(string(body), `"status":"cancelled"`) {
		t.Fatalf("recovered operator readback = %d body=%s", code, body)
	}
	if healed, err := reconcilePendingCACeremonyCancels(ctx, h.store, h.log); err != nil || healed != 0 {
		t.Fatalf("second recovery = %d, %v; want no pending command", healed, err)
	}
}
