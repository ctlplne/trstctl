// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
)

func pkiSecretPreviewRequest(t *testing.T, h *servedHarness, token string, body map[string]any) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal PKI-secret preview: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, h.ts.URL+"/api/v1/secrets/pki/preview", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new PKI-secret preview: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do PKI-secret preview: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

func TestServedPKISecretPreviewIsExactEffectFreeAndBindsExecution(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "served PKI-secret preview tenant")
	token := seedScopedToken(t, h.store, h.tenant, "secrets:write", "audit:read")

	requesterKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer requesterKey.Destroy()
	csrDER, err := crypto.CreateCertificateRequest(
		crypto.CertificateRequestTemplate{CommonName: "preview-pki.example.test", DNSNames: []string{"preview-pki.example.test"}},
		requesterKey,
	)
	if err != nil {
		t.Fatalf("create requester CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	defer wipeTestBytes(csrPEM)
	request := map[string]any{"csr_pem": string(csrPEM), "ttl_seconds": 900}
	beforeEvents := pkiPreviewTenantEventCount(t, h.log, h.tenant)

	status, body := pkiSecretPreviewRequest(t, h, token, request)
	if status != http.StatusOK {
		t.Fatalf("CSR preview = %d: %s", status, body)
	}
	if bytes.Contains(body, csrPEM) || bytes.Contains(body, []byte("PRIVATE KEY")) || bytes.Contains(body, []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("preview returned request or credential material: %s", body)
	}
	var plan struct {
		Capability             string   `json:"capability"`
		Operation              string   `json:"operation"`
		Ready                  bool     `json:"ready"`
		EffectFree             bool     `json:"effect_free"`
		CustodyMode            string   `json:"custody_mode"`
		CommonName             string   `json:"common_name"`
		RequestedTTLSeconds    int      `json:"requested_ttl_seconds"`
		EffectiveTTLSeconds    int      `json:"effective_ttl_seconds"`
		Profile                string   `json:"profile"`
		CACertificateSHA256    string   `json:"ca_certificate_sha256"`
		CSRSHA256              string   `json:"csr_sha256"`
		SubjectKeyAlgorithm    string   `json:"subject_key_algorithm"`
		SubjectKeyBits         int      `json:"subject_key_bits"`
		RequiredPermission     string   `json:"required_permission"`
		RequestFingerprint     string   `json:"request_fingerprint"`
		VaultPath              string   `json:"vault_path"`
		Blockers               []string `json:"blockers"`
		PreviewWrites          []string `json:"preview_writes"`
		PreviewExternalEffects []string `json:"preview_external_effects"`
		ExecuteWrites          []string `json:"execute_writes"`
		ExecuteExternalEffects []string `json:"execute_external_effects"`
		RecoverySteps          []string `json:"recovery_steps"`
		VerificationSteps      []string `json:"verification_steps"`
		CLIArgv                []string `json:"cli_argv"`
		DataHandling           string   `json:"secret_data_handling"`
		Prerequisites          []struct {
			ID          string `json:"id"`
			Ready       bool   `json:"ready"`
			Detail      string `json:"detail"`
			Remediation string `json:"remediation"`
		} `json:"prerequisites"`
	}
	if err := json.Unmarshal(body, &plan); err != nil {
		t.Fatalf("decode PKI-secret preview: %v (%s)", err, body)
	}
	if plan.Capability != "F67" || plan.Operation != "issue_certificate" || !plan.Ready || !plan.EffectFree ||
		plan.CustodyMode != "requester_csr" || plan.CommonName != "preview-pki.example.test" ||
		plan.RequestedTTLSeconds != 900 || plan.EffectiveTTLSeconds != 900 || plan.Profile != "secrets-api" ||
		!strings.HasPrefix(plan.CACertificateSHA256, "sha256:") || !strings.HasPrefix(plan.CSRSHA256, "sha256:") ||
		plan.SubjectKeyAlgorithm != "ECDSA" || plan.SubjectKeyBits != 256 || plan.RequiredPermission != "secrets:write" ||
		!strings.HasPrefix(plan.RequestFingerprint, "sha256:") || plan.VaultPath != "/v1/pki/sign/default" {
		t.Fatalf("unexpected CSR preview: %+v", plan)
	}
	if len(plan.Blockers) != 0 || len(plan.PreviewWrites) != 0 || len(plan.PreviewExternalEffects) != 0 ||
		len(plan.ExecuteWrites) == 0 || len(plan.ExecuteExternalEffects) == 0 || len(plan.RecoverySteps) == 0 ||
		len(plan.VerificationSteps) == 0 || len(plan.CLIArgv) == 0 || plan.DataHandling == "" {
		t.Fatalf("preview omitted lifecycle or zero-effect evidence: %+v", plan)
	}
	for _, id := range []string{"secrets_api", "issuing_ca", "custody_input", "revocation_tracking"} {
		found := false
		for _, prerequisite := range plan.Prerequisites {
			if prerequisite.ID == id {
				found = true
				if !prerequisite.Ready || prerequisite.Detail == "" {
					t.Fatalf("prerequisite %s is not ready and explained: %+v", id, prerequisite)
				}
			}
		}
		if !found {
			t.Fatalf("preview omitted prerequisite %s: %+v", id, plan.Prerequisites)
		}
	}
	if afterEvents := pkiPreviewTenantEventCount(t, h.log, h.tenant); afterEvents != beforeEvents {
		t.Fatalf("effect-free preview changed tenant events: before=%d after=%d", beforeEvents, afterEvents)
	}

	status, replayBody := pkiSecretPreviewRequest(t, h, token, request)
	if status != http.StatusOK || !bytes.Contains(replayBody, []byte(plan.RequestFingerprint)) {
		t.Fatalf("same preview did not return stable fingerprint: %d %s", status, replayBody)
	}
	status, changedBody := pkiSecretPreviewRequest(t, h, token, map[string]any{"csr_pem": string(csrPEM), "ttl_seconds": 901})
	if status != http.StatusOK || bytes.Contains(changedBody, []byte(plan.RequestFingerprint)) {
		t.Fatalf("changed TTL did not invalidate preview fingerprint: %d %s", status, changedBody)
	}

	status, staleBody := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/pki", token, map[string]any{
		"csr_pem": string(csrPEM), "ttl_seconds": 901, "preview_fingerprint": plan.RequestFingerprint,
	})
	if status != http.StatusConflict || !bytes.Contains(staleBody, []byte("reviewed PKI issuance plan is stale")) ||
		bytes.Contains(staleBody, []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("stale reviewed execution did not fail closed: %d %s", status, staleBody)
	}
	status, issuedBody := secretsReq(t, h, http.MethodPost, "/api/v1/secrets/pki", token, map[string]any{
		"csr_pem": string(csrPEM), "ttl_seconds": 900, "preview_fingerprint": plan.RequestFingerprint,
	})
	if status != http.StatusCreated || !bytes.Contains(issuedBody, []byte("BEGIN CERTIFICATE")) || bytes.Contains(issuedBody, []byte("PRIVATE KEY")) {
		t.Fatalf("reviewed CSR execution = %d: %s", status, issuedBody)
	}

	status, legacyBody := pkiSecretPreviewRequest(t, h, token, map[string]any{
		"common_name": "legacy-preview.example.test", "ttl_seconds": 900,
	})
	if status != http.StatusOK || !bytes.Contains(legacyBody, []byte(`"custody_mode":"deprecated_server_keygen"`)) ||
		!bytes.Contains(legacyBody, []byte(`"vault_path":"/v1/pki/issue/default"`)) ||
		!bytes.Contains(legacyBody, []byte(`"id":"durable_deprecation_evidence"`)) {
		t.Fatalf("legacy preview did not explain custody and durable evidence: %d %s", status, legacyBody)
	}
	if got := eventCount(t, h.log, h.tenant, "issuance.server_side_keygen"); got != 0 {
		t.Fatalf("legacy preview appended %d deprecation events", got)
	}
}

func TestServedPKISecretPreviewRejectsInvalidConfigurationWithoutIdempotencyKey(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	token := seedScopedToken(t, h.store, h.tenant, "secrets:write")
	for name, input := range map[string]map[string]any{
		"missing custody":   {"ttl_seconds": 900},
		"ambiguous custody": {"common_name": "ambiguous.example.test", "csr_pem": "not-a-csr", "ttl_seconds": 900},
		"negative TTL":      {"common_name": "negative.example.test", "ttl_seconds": -1},
		"malformed CSR":     {"csr_pem": "not-a-csr", "ttl_seconds": 900},
	} {
		status, body := pkiSecretPreviewRequest(t, h, token, input)
		if status != http.StatusBadRequest {
			t.Fatalf("%s preview = %d, want 400: %s", name, status, body)
		}
	}
}

func pkiPreviewTenantEventCount(t *testing.T, log *events.Log, tenantID string) int {
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
