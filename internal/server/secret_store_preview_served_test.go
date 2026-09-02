// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

func secretStorePreviewRequest(t *testing.T, h *servedHarness, token string, body map[string]any) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal preview request: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/secrets/store/preview", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new preview request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do preview request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

func TestServedSecretStoreCreatePreviewIsExactAndEffectFree(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "served native secret create preview tenant")
	owner, err := h.store.CreateOwner(t.Context(), store.Owner{
		TenantID: h.tenant, Kind: store.OwnerService, Name: "Payments platform", Environment: "production",
	})
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	const fixtureValue = "f63-preview-must-never-escape"
	input := map[string]any{"name": "app/payments/api", "owner_id": owner.ID, "value": fixtureValue}

	status, body := secretStorePreviewRequest(t, h, token, input)
	if status != http.StatusOK {
		t.Fatalf("preview status = %d body %s", status, body)
	}
	if strings.Contains(string(body), fixtureValue) {
		t.Fatalf("preview echoed the secret value: %s", body)
	}
	var plan struct {
		Capability             string   `json:"capability"`
		Operation              string   `json:"operation"`
		Ready                  bool     `json:"ready"`
		EffectFree             bool     `json:"effect_free"`
		Name                   string   `json:"name"`
		OwnerID                string   `json:"owner_id"`
		NextVersion            int      `json:"next_version"`
		RequiredPermission     string   `json:"required_permission"`
		RequestFingerprint     string   `json:"request_fingerprint"`
		Blockers               []string `json:"blockers"`
		PreviewWrites          []string `json:"preview_writes"`
		PreviewExternalEffects []string `json:"preview_external_effects"`
		ExecuteWrites          []string `json:"execute_writes"`
		RecoverySteps          []string `json:"recovery_steps"`
		DataHandling           string   `json:"secret_data_handling"`
	}
	if err := json.Unmarshal(body, &plan); err != nil {
		t.Fatalf("decode preview: %v (%s)", err, body)
	}
	if plan.Capability != "F63" || plan.Operation != "create" || !plan.Ready || !plan.EffectFree ||
		plan.Name != "app/payments/api" || plan.OwnerID != owner.ID || plan.NextVersion != 1 ||
		plan.RequiredPermission != "secrets:write" || !strings.HasPrefix(plan.RequestFingerprint, "sha256:") {
		t.Fatalf("unexpected preview plan: %+v", plan)
	}
	if len(plan.Blockers) != 0 || len(plan.PreviewWrites) != 0 || len(plan.PreviewExternalEffects) != 0 ||
		len(plan.ExecuteWrites) == 0 || len(plan.RecoverySteps) == 0 || plan.DataHandling == "" {
		t.Fatalf("preview did not publish an exact zero-effect boundary: %+v", plan)
	}
	if _, err := h.store.GetSecret(t.Context(), h.tenant, "app/payments/api"); !errors.Is(err, store.ErrSecretNotFound) {
		t.Fatalf("preview changed the native store: %v", err)
	}
	if h.hasEvent(t, "secret.created") || h.logContains(t, fixtureValue) {
		t.Fatal("preview appended an event or leaked plaintext")
	}
	const otherTenant = "22222222-2222-4222-8222-222222222263"
	otherOwner, err := h.store.CreateOwner(t.Context(), store.Owner{
		TenantID: otherTenant, Kind: store.OwnerService, Name: "Other tenant owner", Environment: "production",
	})
	if err != nil {
		t.Fatalf("create cross-tenant owner: %v", err)
	}
	status, crossTenantBody := secretStorePreviewRequest(t, h, token, map[string]any{
		"name": "app/payments/cross-tenant", "owner_id": otherOwner.ID, "value": fixtureValue,
	})
	if status != http.StatusOK || !strings.Contains(string(crossTenantBody), `"ready":false`) ||
		!strings.Contains(string(crossTenantBody), "does not exist in this tenant") || strings.Contains(string(crossTenantBody), otherOwner.Name) {
		t.Fatalf("cross-tenant owner preview did not fail closed and redact neighbor metadata: status %d body %s", status, crossTenantBody)
	}
	if _, err := h.store.GetSecret(t.Context(), h.tenant, "app/payments/cross-tenant"); !errors.Is(err, store.ErrSecretNotFound) {
		t.Fatalf("cross-tenant preview changed the native store: %v", err)
	}

	status, replayBody := secretStorePreviewRequest(t, h, token, input)
	if status != http.StatusOK {
		t.Fatalf("preview replay status = %d body %s", status, replayBody)
	}
	var replay struct {
		RequestFingerprint string `json:"request_fingerprint"`
	}
	if err := json.Unmarshal(replayBody, &replay); err != nil || replay.RequestFingerprint != plan.RequestFingerprint {
		t.Fatalf("same preview did not return the same keyed fingerprint: %q != %q (%v)", replay.RequestFingerprint, plan.RequestFingerprint, err)
	}
	changed := map[string]any{"name": "app/payments/api", "owner_id": owner.ID, "value": fixtureValue + "-changed"}
	status, changedBody := secretStorePreviewRequest(t, h, token, changed)
	if status != http.StatusOK {
		t.Fatalf("changed preview status = %d body %s", status, changedBody)
	}
	var changedPlan struct {
		RequestFingerprint string `json:"request_fingerprint"`
	}
	if err := json.Unmarshal(changedBody, &changedPlan); err != nil || changedPlan.RequestFingerprint == plan.RequestFingerprint {
		t.Fatalf("changed secret value did not invalidate the keyed plan: %q (%v)", changedPlan.RequestFingerprint, err)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/store", token, input)
	if status != http.StatusCreated {
		t.Fatalf("execute reviewed create: status %d body %s", status, body)
	}
	status, body = secretStorePreviewRequest(t, h, token, input)
	if status != http.StatusOK || !strings.Contains(string(body), `"ready":false`) || !strings.Contains(string(body), "already exists") {
		t.Fatalf("existing-name preview did not fail closed: status %d body %s", status, body)
	}
}
