// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func TestCR064ObserverEventStopsAfterConfigurerLosesSecretRead(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	configurer := seedScopedTokenSubject(t, h.store, h.tenant, "observer-configurer", "secrets:read", "secrets:write", "notifications:write")
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "observer-admin", "*")
	const ref = "secret://observers/cr064/hmac"
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", configurer, uuid.NewString(), map[string]any{
		"name": "observers/cr064/hmac", "value": "fixture-observer-key",
	}); status != http.StatusCreated {
		t.Fatalf("store observer secret: %d %s", status, body)
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/observers", configurer, uuid.NewString(), map[string]any{
		"name": "cr064-observer", "events_url": "https://observer.example.test/events", "credential_ref": ref,
	})
	if status != http.StatusCreated {
		t.Fatalf("register observer: %d %s", status, body)
	}
	var observer struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &observer); err != nil || observer.ID == "" {
		t.Fatalf("observer ID: %v %s", err, body)
	}
	row, err := h.store.GetExternalObserver(t.Context(), h.tenant, observer.ID)
	if err != nil || row.CredentialRef != ref || row.ConfiguredBy != "observer-configurer" {
		t.Fatalf("observer credential: %+v, %v", row, err)
	}
	requests := 0
	h.srv.observerEvents.skipEndpointValidation = true
	h.srv.observerEvents.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.Header.Get(observerEventSignatureHeader) == "" {
			t.Error("observer event was unsigned")
		}
		return &http.Response{StatusCode: http.StatusAccepted, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
	})}
	payload, err := json.Marshal(observerEventEnvelope{ObserverID: observer.ID, Event: json.RawMessage(`{"type":"rotation.completed"}`)})
	if err != nil {
		t.Fatal(err)
	}
	message := orchestrator.Message{TenantID: h.tenant, Payload: payload}
	if err := h.srv.observerEvents.Deliver(t.Context(), message); err != nil || requests != 1 {
		t.Fatalf("authorized observer delivery: requests=%d err=%v", requests, err)
	}
	tokens, err := h.store.ListAPITokensPage(t.Context(), h.tenant, store.ZeroUUID, "observer-configurer", false, 10)
	if err != nil || len(tokens) != 1 {
		t.Fatalf("configurer token lookup: %d, %v", len(tokens), err)
	}
	if status, body := secretsReqKey(t, h, http.MethodDelete, "/api/v1/access/api-tokens/"+tokens[0].ID, admin, uuid.NewString(), nil); status != http.StatusNoContent {
		t.Fatalf("revoke configurer token: %d %s", status, body)
	}
	if err := h.srv.observerEvents.Deliver(t.Context(), message); err == nil || requests != 1 {
		t.Fatalf("revoked configurer still receives event: requests=%d err=%v", requests, err)
	}
	if status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/observers/"+observer.ID, admin, uuid.NewString(), map[string]any{
		"name": "cr064-observer", "events_url": "https://observer.example.test/events", "credential_ref": ref,
	}); status != http.StatusOK {
		t.Fatalf("authorized observer re-save: %d %s", status, body)
	}
	row, err = h.store.GetExternalObserver(t.Context(), h.tenant, observer.ID)
	if err != nil || row.ConfiguredBy != "observer-admin" {
		t.Fatalf("re-saved observer authority: %+v, %v", row, err)
	}
	if err := h.srv.observerEvents.Deliver(t.Context(), message); err != nil || requests != 2 {
		t.Fatalf("re-authorized observer delivery: requests=%d err=%v", requests, err)
	}
}
