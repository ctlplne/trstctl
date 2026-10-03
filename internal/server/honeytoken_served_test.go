// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/config"
)

// A planted trstctl credential must be harmless when stolen yet produce a
// durable, tenant-bound incident from a stock Bearer request. This is the first
// local honeytoken journey; AWS CloudTrail detection needs separate proof.
func TestServedHoneytokenPlantTriggerInvestigateAndRetire(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	owner := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write", "notifications:read")
	reader := seedScopedToken(t, h.store, h.tenant, "secrets:read")
	status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens", reader, "honey-reader-plant", map[string]any{
		"name": "unauthorized-decoy", "placement": "payments/ci",
	})
	if status != http.StatusForbidden {
		t.Fatalf("read-only caller planted a decoy: HTTP %d, want 403", status)
	}
	status, _ = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens", owner, "honey-invalid-1", map[string]any{
		"name": "alert\ninjection", "placement": "payments/ci",
	})
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("control-character decoy name: HTTP %d, want 422", status)
	}
	request := map[string]any{"name": "qa-payments-decoy", "placement": "payments/ci"}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens", owner, "honey-plant-1", request)
	if status != http.StatusCreated {
		t.Fatalf("plant honeytoken: HTTP %d, want 201", status)
	}
	var planted struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		State string `json:"state"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &planted); err != nil {
		t.Fatalf("decode plant response: %v", err)
	}
	if planted.ID == "" || planted.Name != "qa-payments-decoy" || planted.State != "active" ||
		!strings.HasPrefix(planted.Token, auth.TokenPrefix) {
		t.Fatal("plant did not return one usable decoy credential")
	}
	if h.logContains(t, planted.Token) {
		t.Fatal("decoy bearer leaked into the event log")
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens", owner, "honey-plant-1", request)
	if status != http.StatusCreated {
		t.Fatalf("idempotent plant replay: HTTP %d", status)
	}
	var replayed struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &replayed); err != nil || replayed.ID != planted.ID || replayed.Token != planted.Token {
		t.Fatal("plant replay created or returned a different decoy")
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/honeytokens/"+planted.ID, owner, nil)
	if status != http.StatusOK || strings.Contains(string(body), planted.Token) {
		t.Fatalf("metadata read HTTP %d or revealed the bearer", status)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/honeytokens/"+planted.ID, reader, nil)
	if status != http.StatusOK || strings.Contains(string(body), planted.Token) {
		t.Fatalf("read-only caller could not inspect safe metadata, or saw the bearer: HTTP %d", status)
	}
	status, _ = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/"+planted.ID+"/revoke", reader, "honey-reader-retire", nil)
	if status != http.StatusForbidden {
		t.Fatalf("read-only caller retired a decoy: HTTP %d, want 403", status)
	}

	status, _ = secretsReq(t, h, http.MethodGet, "/api/v1/access/roles", planted.Token, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("decoy granted access: HTTP %d, want 401", status)
	}
	if !h.hasEvent(t, "honeytoken.triggered") {
		t.Fatal("decoy use did not append a trigger event")
	}
	var alerts int
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = 'notification.honeytoken'`,
		h.tenant).Scan(&alerts); err != nil || alerts != 1 {
		t.Fatalf("decoy trigger did not queue one durable alert: count=%d err=%v", alerts, err)
	}
	// The edge detector also observes a bearer sent to a public route. Such
	// routes bypass the ordinary RBAC resolver, so this needs an independent bait.
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens", owner, "honey-plant-public", map[string]any{
		"name": "qa-public-route-decoy", "placement": "docs/example",
	})
	if status != http.StatusCreated {
		t.Fatalf("plant public-route decoy: HTTP %d", status)
	}
	var publicBait struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &publicBait); err != nil || publicBait.Token == "" {
		t.Fatal("public-route decoy has no bearer")
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/honeytokens?limit=1", owner, nil)
	var firstPage struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
		NextCursor string `json:"next_cursor"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &firstPage) != nil || len(firstPage.Items) != 1 || firstPage.NextCursor == "" ||
		strings.Contains(string(body), publicBait.Token) {
		t.Fatalf("first metadata page did not limit, continue, or protect the bearer: HTTP %d", status)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/honeytokens?limit=1&cursor="+firstPage.NextCursor, owner, nil)
	var secondPage struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &secondPage) != nil || len(secondPage.Items) != 1 ||
		secondPage.Items[0].ID == firstPage.Items[0].ID {
		t.Fatalf("second metadata page did not advance: HTTP %d", status)
	}
	status, _ = secretsReq(t, h, http.MethodGet, "/api/v1/openapi.json", publicBait.Token, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("public route accepted decoy bearer: HTTP %d", status)
	}
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = 'notification.honeytoken'`,
		h.tenant).Scan(&alerts); err != nil || alerts != 2 {
		t.Fatalf("public route did not queue a separate alert: count=%d err=%v", alerts, err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/honeytokens/"+planted.ID, owner, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"state":"triggered"`) ||
		!strings.Contains(string(body), `"trigger_method":"GET"`) ||
		!strings.Contains(string(body), `"trigger_path":"/api/v1/access/roles"`) ||
		strings.Contains(string(body), planted.Token) {
		t.Fatalf("investigation metadata HTTP %d lacks trigger or revealed bearer", status)
	}
	status, _ = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/honeytokens/"+planted.ID+"/revoke", owner, "honey-retire-1", nil)
	if status != http.StatusOK {
		t.Fatalf("retire honeytoken: HTTP %d", status)
	}
	status, _ = secretsReq(t, h, http.MethodGet, "/api/v1/access/roles", planted.Token, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("retired decoy granted access: HTTP %d", status)
	}
}
