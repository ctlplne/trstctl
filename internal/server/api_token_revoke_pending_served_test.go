// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A process can stop after the independent SQL claim and before publishing
// its event. The bearer must remain denied, and a cold worker must publish the
// same first command once rather than inventing a second revocation.
func TestServedAPITokenRevocationClaimBeforeAppendRecovers(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	raw := seedScopedToken(t, h.store, h.tenant, "access:read")
	hash, err := auth.HashAPIToken([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := h.store.LookupAPITokenByHash(t.Context(), hash)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(projections.APITokenRevoked{
		ID: rec.ID, Reason: "preappend fault", RevokedBy: "qa-operator",
	})
	if err != nil {
		t.Fatal(err)
	}
	eventID := uuid.NewString()
	first := store.APITokenRevocationCommand{
		TenantID: h.tenant, TokenID: rec.ID,
		Event: events.Event{
			ID: eventID, TenantID: h.tenant, Type: projections.EventAPITokenRevoked,
			SchemaVersion: events.DefaultSchemaVersion,
			Time:          time.Now().UTC().Truncate(time.Microsecond), Data: payload,
		},
	}
	claimed, created, err := h.store.ClaimAPITokenRevocationCommand(t.Context(), first)
	if err != nil || !created || claimed.Event.ID != eventID {
		t.Fatalf("first preappend claim: created=%v command=%+v err=%v", created, claimed, err)
	}
	if status, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/access/roles", raw, "", nil); status != http.StatusUnauthorized {
		t.Fatalf("preappend fence admitted bearer: status=%d body=%s", status, body)
	}
	stale, err := h.store.GetAPIToken(t.Context(), h.tenant, rec.ID)
	if err != nil || stale.RevokedAt != nil {
		t.Fatalf("preappend fixture should keep SQL read model stale: row=%+v err=%v", stale, err)
	}
	second := first
	second.Event.ID = uuid.NewString()
	second.Event.Data = []byte(`{"id":"` + rec.ID + `","reason":"competing command"}`)
	if _, _, err := h.store.ClaimAPITokenRevocationCommand(t.Context(), second); err == nil {
		t.Fatal("different first-writer command displaced the pending revocation")
	}
	if healed, err := h.srv.orch.ReconcilePendingAPITokenRevocations(t.Context()); err != nil || healed != 1 {
		t.Fatalf("recover unpublished first command: healed=%d err=%v", healed, err)
	}
	if healed, err := h.srv.orch.ReconcilePendingAPITokenRevocations(t.Context()); err != nil || healed != 0 {
		t.Fatalf("duplicate recovery: healed=%d err=%v", healed, err)
	}
	if status, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/access/roles", raw, "", nil); status != http.StatusUnauthorized {
		t.Fatalf("reconciled token admitted bearer: status=%d body=%s", status, body)
	}
	if retained, found, err := h.log.EventByID(t.Context(), eventID); err != nil || !found ||
		retained.Type != projections.EventAPITokenRevoked || string(retained.Data) != string(payload) {
		t.Fatalf("recovered first event: found=%v event=%+v err=%v", found, retained, err)
	}
	if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("cold read-model replay: %v", err)
	}
	if status, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/access/roles", raw, "", nil); status != http.StatusUnauthorized {
		t.Fatalf("replay reopened token: status=%d body=%s", status, body)
	}
}

// A durable revocation must stop bearer admission even when its SQL read model
// has not yet caught up. The trigger interrupts only this disposable token's
// projection after the event log has accepted the command.
func TestServedAPITokenRevokeRefusesBearerDuringProjectionGap(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	admin := seedScopedToken(t, h.store, h.tenant, "access:read", "access:write")
	target := seedScopedToken(t, h.store, h.tenant, "access:read")
	hash, err := auth.HashAPIToken([]byte(target))
	if err != nil {
		t.Fatal(err)
	}
	token, err := h.store.LookupAPITokenByHash(t.Context(), hash)
	if err != nil {
		t.Fatal(err)
	}
	if status, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/access/roles", target, "", nil); status != http.StatusOK {
		t.Fatalf("target bearer baseline: status=%d body=%s", status, body)
	}

	const trigger = "qa_api_token_revoke_projection_fail"
	const function = "qa_api_token_revoke_projection_fail_fn"
	clearFault := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := h.store.SystemPool().Exec(ctx,
			"DROP TRIGGER IF EXISTS "+trigger+" ON api_tokens; DROP FUNCTION IF EXISTS "+function+"()")
		if err != nil {
			t.Errorf("clear owned projection fault: %v", err)
		}
	}
	t.Cleanup(clearFault)
	_, err = h.store.SystemPool().Exec(t.Context(), fmt.Sprintf(`
		CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.id = '%s'::uuid AND NEW.revoked_at IS NOT NULL THEN
				RAISE EXCEPTION 'owned API-token revoke projection fault';
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER %s BEFORE UPDATE ON api_tokens
		FOR EACH ROW EXECUTE FUNCTION %s()`, function, token.ID, trigger, function))
	if err != nil {
		t.Fatalf("install owned projection fault: %v", err)
	}

	status, body := secretsReqKey(t, h, http.MethodDelete,
		"/api/v1/access/api-tokens/"+token.ID, admin, "qa-revoke-projection-gap",
		map[string]string{"reason": "owned projection-gap drill"})
	if status != http.StatusInternalServerError {
		t.Fatalf("injected projection fault did not interrupt served revoke: status=%d body=%s", status, body)
	}
	revocations := 0
	if err := h.log.Replay(t.Context(), 0, func(event events.Event) error {
		if event.Type != projections.EventAPITokenRevoked || event.TenantID != h.tenant {
			return nil
		}
		var payload projections.APITokenRevoked
		if err := json.Unmarshal(event.Data, &payload); err != nil {
			return err
		}
		if payload.ID == token.ID {
			revocations++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if revocations != 1 {
		t.Fatalf("retained target revoke events=%d, want 1", revocations)
	}
	stale, err := h.store.GetAPIToken(t.Context(), h.tenant, token.ID)
	if err != nil || stale.RevokedAt != nil {
		t.Fatalf("owned fault did not leave SQL stale: row=%+v err=%v", stale, err)
	}
	status, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/access/roles", target, "", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("durably revoked bearer admitted while projection is stale: status=%d body=%s", status, body)
	}

	clearFault()
	if healed, err := h.srv.orch.ReconcilePendingAPITokenRevocations(t.Context()); err != nil || healed != 1 {
		t.Fatalf("recover retained revoke: healed=%d err=%v", healed, err)
	}
	if status, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/access/roles", target, "", nil); status != http.StatusUnauthorized {
		t.Fatalf("recovered bearer admission: status=%d body=%s", status, body)
	}
	if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("cold rebuild retained revoke: %v", err)
	}
	if status, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/access/roles", target, "", nil); status != http.StatusUnauthorized {
		t.Fatalf("cold-rebuilt bearer admission: status=%d body=%s", status, body)
	}
}
