// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/store"
)

// CR-020: a token creator's access:write grant is not authority to assume an
// arbitrary person's subject and thereby become their requester or minter.
func TestServedAPITokenCreatorCannotNameAnotherPerson(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	creator := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "cr020-creator", []string{"access:write", "owners:read"})
	path := "/api/v1/access/api-tokens"
	code, _ := doBearer(t, h.ts, http.MethodPost, path, creator, "cr020-impersonate",
		map[string]any{"subject": "cr020-victim", "scopes": []string{"owners:read"}})
	if code != http.StatusForbidden {
		t.Fatalf("creator minted a token in another person's name: HTTP %d", code)
	}
	code, body := doBearer(t, h.ts, http.MethodPost, path, creator, "cr020-self",
		map[string]any{"subject": "cr020-creator", "scopes": []string{"owners:read"}})
	if code != http.StatusCreated {
		t.Fatalf("creator could not mint its own attenuated token: HTTP %d %s", code, body)
	}
	var own struct {
		Subject  string `json:"subject"`
		MintedBy string `json:"minted_by"`
	}
	if err := json.Unmarshal(body, &own); err != nil || own.Subject != "cr020-creator" || own.MintedBy != own.Subject {
		t.Fatalf("self token subject/minter = %q/%q err=%v", own.Subject, own.MintedBy, err)
	}
}

// The short-lived endpoint shares the API-token command and must apply the
// same subject rule. A preview fingerprint is a request digest, not a grant to
// impersonate its named subject.
func TestServedEphemeralAPIKeyCannotNameAnotherPerson(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	creator := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "cr020-ephemeral-creator", []string{"access:write", "owners:read"})
	request := map[string]any{"subject": "cr020-ephemeral-victim", "scopes": []string{"owners:read"}, "ttl_seconds": 300}
	for _, path := range []string{"/api/v1/ephemeral/api-keys/preview", "/api/v1/ephemeral/api-keys"} {
		code, _ := doBearer(t, h.ts, http.MethodPost, path, creator, "cr020-ephemeral-cross", request)
		if code != http.StatusForbidden {
			t.Fatalf("short-lived key route %s accepted another person's subject: HTTP %d", path, code)
		}
	}
}

// Historical delegated mints retain their authenticated event actor as their
// minter. Offboarding that actor must cut the bearer off even when its subject
// remains active; a replay must retain the same linkage.
func TestServedAPITokenMinterOffboardRevokesLegacyDelegation(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	admin := seedServedAPIToken(t, context.Background(), h.store, h.tenant, "cr020-admin", []string{"*"})
	const minter = "cr020-minter"
	if code, _ := doBearer(t, h.ts, http.MethodPut, "/api/v1/access/members/"+minter, admin,
		"cr020-member", map[string]any{"roles": []string{}, "source": "manual"}); code != http.StatusOK {
		t.Fatalf("create active minter member = HTTP %d", code)
	}
	actorCtx := events.ContextWithActor(context.Background(), events.Actor{Subject: minter})
	rec, raw, err := h.srv.orch.CreateAPIToken(actorCtx, h.tenant, "cr020-victim", []string{"owners:read"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	bearer := secrettext.String(raw)
	secret.Wipe(raw)
	var retained int
	if err := h.log.Replay(context.Background(), 0, func(ev events.Event) error {
		if ev.TenantID != h.tenant || ev.Type != projections.EventAPITokenCreated {
			return nil
		}
		var payload projections.APITokenCreated
		if err := json.Unmarshal(ev.Data, &payload); err != nil {
			return err
		}
		if payload.ID == rec.ID {
			retained++
			if ev.Actor == nil || ev.Actor.Subject != minter || payload.Subject != "cr020-victim" {
				t.Errorf("retained token event lost authenticated minter or intended subject")
			}
		}
		return nil
	}); err != nil || retained != 1 {
		t.Fatalf("retained token provenance count=%d err=%v", retained, err)
	}
	if code, _ := doBearer(t, h.ts, http.MethodGet, "/api/v1/owners", bearer, "", nil); code != http.StatusOK {
		t.Fatalf("historical delegated bearer before minter offboard = HTTP %d", code)
	}
	list := func() struct {
		Items []struct {
			ID       string  `json:"id"`
			MintedBy string  `json:"minted_by"`
			Revoked  *string `json:"revoked_at"`
		} `json:"items"`
	} {
		t.Helper()
		code, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/access/api-tokens?subject=cr020-victim&include_revoked=true", admin, "", nil)
		var out struct {
			Items []struct {
				ID       string  `json:"id"`
				MintedBy string  `json:"minted_by"`
				Revoked  *string `json:"revoked_at"`
			} `json:"items"`
		}
		if code != http.StatusOK || json.Unmarshal(body, &out) != nil || len(out.Items) != 1 || out.Items[0].ID != rec.ID {
			t.Fatalf("legacy delegated token metadata = HTTP %d", code)
		}
		return out
	}
	if got := list().Items[0]; got.MintedBy != minter || got.Revoked != nil {
		t.Fatalf("live delegated token minter/revocation = %q/%v", got.MintedBy, got.Revoked)
	}
	code, _ := doBearer(t, h.ts, http.MethodPost, "/api/v1/access/members/"+minter+"/offboard", admin,
		"cr020-offboard", map[string]any{"reason": "departed"})
	if code != http.StatusOK {
		t.Fatalf("offboard minter = HTTP %d", code)
	}
	if code, _ := doBearer(t, h.ts, http.MethodGet, "/api/v1/owners", bearer, "", nil); code != http.StatusUnauthorized {
		t.Fatalf("delegated bearer after minter offboard = HTTP %d, want 401", code)
	}
	if got := list().Items[0]; got.MintedBy != minter || got.Revoked == nil {
		t.Fatalf("offboarded delegated token minter/revocation = %q/%v", got.MintedBy, got.Revoked)
	}
	// A queued internal mint with this actor must not append a new token after
	// the offboard. Otherwise a later rehire could make that token usable.
	_, lateRaw, err := h.srv.orch.CreateAPIToken(actorCtx, h.tenant, "cr020-victim", []string{"owners:read"}, nil)
	secret.Wipe(lateRaw)
	if !errors.Is(err, store.ErrTenantMemberOffboarded) {
		t.Fatalf("offboarded minter appended a new delegated token: %v", err)
	}
}
