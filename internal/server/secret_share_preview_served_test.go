// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func secretSharePreviewRequest(t *testing.T, h *servedHarness, token string, ttlSeconds int) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"ttl_seconds": ttlSeconds})
	if err != nil {
		t.Fatalf("marshal share preview: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/secrets/shares/preview", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new share preview: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do share preview: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func sharePreviewEventCount(t *testing.T, log *events.Log, tenantID string) int {
	t.Helper()
	count := 0
	if err := log.Replay(t.Context(), 0, func(event events.Event) error {
		if event.TenantID == tenantID {
			count++
		}
		return nil
	}); err != nil {
		t.Fatalf("count tenant events: %v", err)
	}
	return count
}

func TestServedSecretSharePreviewIsEffectFreeAndBindsRecoverableCreate(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "served F60 review and recovery tenant")
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	beforeEvents := sharePreviewEventCount(t, h.log, h.tenant)
	var beforeShares int
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT COUNT(*) FROM secret_shares WHERE tenant_id = $1`, h.tenant).Scan(&beforeShares); err != nil {
		t.Fatalf("count shares before preview: %v", err)
	}

	status, body := secretSharePreviewRequest(t, h, token, 300)
	if status != http.StatusOK {
		t.Fatalf("share preview = %d: %s", status, body)
	}
	var plan struct {
		Capability                        string   `json:"capability"`
		Operation                         string   `json:"operation"`
		Ready                             bool     `json:"ready"`
		EffectFree                        bool     `json:"effect_free"`
		RequestedTTLSeconds               int      `json:"requested_ttl_seconds"`
		EffectiveTTLSeconds               int      `json:"effective_ttl_seconds"`
		RequiredPermission                string   `json:"required_permission"`
		RequestFingerprint                string   `json:"request_fingerprint"`
		SensitiveChangeApprovalConfigured bool     `json:"sensitive_change_approval_configured"`
		Blockers                          []string `json:"blockers"`
		PreviewWrites                     []string `json:"preview_writes"`
		PreviewExternalEffects            []string `json:"preview_external_effects"`
		ExecuteWrites                     []string `json:"execute_writes"`
		ExecuteExternalEffects            []string `json:"execute_external_effects"`
		RecoverySteps                     []string `json:"recovery_steps"`
		VerificationSteps                 []string `json:"verification_steps"`
		CLIArgv                           []string `json:"cli_argv"`
		DataHandling                      string   `json:"secret_data_handling"`
	}
	if err := json.Unmarshal(body, &plan); err != nil {
		t.Fatalf("decode share preview: %v (%s)", err, body)
	}
	if plan.Capability != "F60" || plan.Operation != "create_one_time_share" || !plan.Ready || !plan.EffectFree ||
		plan.RequestedTTLSeconds != 300 || plan.EffectiveTTLSeconds != 300 || plan.RequiredPermission != "secrets:write" ||
		!strings.HasPrefix(plan.RequestFingerprint, "sha256:") || !plan.SensitiveChangeApprovalConfigured {
		t.Fatalf("unexpected share preview: %+v", plan)
	}
	if len(plan.Blockers) != 0 || len(plan.PreviewWrites) != 0 || len(plan.PreviewExternalEffects) != 0 ||
		len(plan.ExecuteWrites) == 0 || len(plan.ExecuteExternalEffects) != 0 || len(plan.RecoverySteps) == 0 ||
		len(plan.VerificationSteps) == 0 || len(plan.CLIArgv) == 0 || plan.DataHandling == "" {
		t.Fatalf("share preview omitted lifecycle or zero-effect evidence: %+v", plan)
	}
	var afterPreviewShares int
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT COUNT(*) FROM secret_shares WHERE tenant_id = $1`, h.tenant).Scan(&afterPreviewShares); err != nil {
		t.Fatalf("count shares after preview: %v", err)
	}
	if afterPreviewShares != beforeShares || sharePreviewEventCount(t, h.log, h.tenant) != beforeEvents {
		t.Fatalf("preview changed durable state: shares %d -> %d, events %d -> %d",
			beforeShares, afterPreviewShares, beforeEvents, sharePreviewEventCount(t, h.log, h.tenant))
	}

	status, replayBody := secretSharePreviewRequest(t, h, token, 300)
	if status != http.StatusOK || !bytes.Contains(replayBody, []byte(plan.RequestFingerprint)) {
		t.Fatalf("same preview did not return stable evidence: %d %s", status, replayBody)
	}
	status, changedBody := secretSharePreviewRequest(t, h, token, 301)
	if status != http.StatusOK || bytes.Contains(changedBody, []byte(plan.RequestFingerprint)) {
		t.Fatalf("changed TTL did not invalidate preview: %d %s", status, changedBody)
	}

	const value = "f60-recoverable-value-must-not-enter-evidence"
	stale := map[string]any{"value": value, "ttl_seconds": 301, "preview_fingerprint": plan.RequestFingerprint}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/shares", token, "f60-stale-plan", stale)
	if status != http.StatusConflict || !bytes.Contains(body, []byte("reviewed one-time share plan is stale")) ||
		bytes.Contains(body, []byte(value)) {
		t.Fatalf("stale share plan did not fail closed: %d %s", status, body)
	}

	reviewed := map[string]any{"value": value, "ttl_seconds": 300, "preview_fingerprint": plan.RequestFingerprint}
	status, createdBody := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/shares", token, "f60-recoverable-create", reviewed)
	if status != http.StatusCreated {
		t.Fatalf("reviewed share create = %d: %s", status, createdBody)
	}
	status, recoveredBody := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/shares", token, "f60-recoverable-create", reviewed)
	if status != http.StatusCreated || !bytes.Equal(createdBody, recoveredBody) {
		t.Fatalf("same-key recovery did not return the exact original result: %d %s", status, recoveredBody)
	}
	var created struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(recoveredBody, &created); err != nil || created.Token == "" {
		t.Fatalf("decode recovered share token: %v (%s)", err, recoveredBody)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/shares/redeem", token, map[string]any{"token": created.Token})
	if status != http.StatusOK || !bytes.Contains(body, []byte(value)) {
		t.Fatalf("redeem recovered share = %d: %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/secrets/shares/redeem", token, map[string]any{"token": created.Token})
	if status != http.StatusNotFound || bytes.Contains(body, []byte(value)) {
		t.Fatalf("second redeem did not fail closed: %d %s", status, body)
	}
	if h.logContains(t, value) || h.logContains(t, created.Token) {
		t.Fatal("event evidence leaked the share value or bearer token")
	}
}

func TestServedSecretSharePreviewRejectsUnsafeTTLWithoutIdempotencyKey(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	token := seedScopedToken(t, h.store, h.tenant, "secrets:write")
	for _, ttl := range []int{-1, 59, 604801} {
		status, body := secretSharePreviewRequest(t, h, token, ttl)
		if status != http.StatusBadRequest {
			t.Fatalf("TTL %d preview = %d, want 400: %s", ttl, status, body)
		}
	}
}
