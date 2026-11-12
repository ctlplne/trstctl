// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/secretstoretest"
)

// OD-14 Done-when (stand-ins written from the public API references): one
// served secret_store source reads 1Password Connect items (vault titles and
// categories, no field value) and Doppler secret names (the names-only
// endpoint) as metadata only; with content inspection a certificate and an
// API key in each become findings and no value is kept; the Secrets posture
// shows both configured with no sync target.
func TestServedSecretStores1PasswordConnectAndDopplerOD14(t *testing.T) {
	der, _, err := ctlogtest.IssueCert("stores.od14.example", "stores.od14.example")
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	apiKey := "gl" + "pat-" + strings.Repeat("Od14Served", 3)[:24]
	op := secretstoretest.NewOnePassword("op-od14", []secretstoretest.OnePasswordItem{
		{Vault: "Payments", Title: "Deploy token", Fields: map[string]string{"credential": apiKey, "username": "deploy-bot"}},
		{Vault: "Payments", Title: "Edge certificate", Category: "DOCUMENT", Fields: map[string]string{"certificate": certPEM}},
		{Vault: "Payments", Title: "Notes", Category: "SECURE_NOTE", Fields: map[string]string{"notesPlain": "rotate quarterly"}},
	})
	t.Cleanup(op.Close)
	dp := secretstoretest.NewDoppler("dp-od14", []secretstoretest.DopplerSecret{
		{Project: "backend", Config: "prd", Name: "DEPLOY_TOKEN", Value: apiKey},
		{Project: "backend", Config: "prd", Name: "TLS_CERT", Value: certPEM},
		{Project: "backend", Config: "prd", Name: "LOG_LEVEL", Value: "info"},
	})
	t.Cleanup(dp.Close)
	t.Setenv("TRSTCTL_OD14_OP", "op-od14")
	t.Setenv("TRSTCTL_OD14_DP", "dp-od14")
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs("env:TRSTCTL_OD14_OP", "env:TRSTCTL_OD14_DP"))
	o := &od13Harness{t: t, h: h, tok: seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "secrets:read", string(authz.PrivateEgress))}
	providers := func(inspect bool) []map[string]any {
		return []map[string]any{
			od13At(t, op.URL(), map[string]any{"provider": "1password-connect", "vaults": []string{"Payments"}, "token_ref": "env:TRSTCTL_OD14_OP", "inspect_content": inspect}),         // #nosec G101 -- credential references to fabricated fixture values (CWE-798)
			od13At(t, dp.URL(), map[string]any{"provider": "doppler", "project": "backend", "configs": []string{"prd"}, "token_ref": "env:TRSTCTL_OD14_DP", "inspect_content": inspect}), // #nosec G101 -- credential references to fabricated fixture values (CWE-798)
		}
	}
	sourceID, run := o.run("od14-metadata", providers(false)...)
	if run.Status != "succeeded" || len(run.TargetResults) != 2 {
		t.Fatalf("metadata run = %+v", run)
	}
	got, body := o.findings(sourceID)
	for _, provider := range []string{"1password-connect", "doppler"} {
		if got[provider+"/cloud_secret_resource"] != 3 || got[provider+"/x509_certificate"]+got[provider+"/secret_store_api_key"] != 0 {
			t.Fatalf("metadata-only findings of %s = %v", provider, got)
		}
	}
	if bytes.Contains(body, []byte(apiKey)) || bytes.Contains(body, []byte("BEGIN CERTIFICATE")) {
		t.Fatal("the metadata-only findings carry a stored value")
	}
	for _, call := range op.Seen() {
		if strings.Contains(call, "/items/") {
			t.Fatalf("a metadata-only 1Password run read item fields: %s", call)
		}
	}
	for _, call := range dp.Seen() {
		if strings.HasPrefix(call, "GET /v3/configs/config/secrets?") {
			t.Fatalf("a metadata-only Doppler run read values: %s", call)
		}
	}
	sourceID, run = o.run("od14-inspect", providers(true)...)
	if run.Status != "succeeded" || len(run.TargetResults) != 2 {
		t.Fatalf("inspect run = %+v", run)
	}
	got, body = o.findings(sourceID)
	for _, provider := range []string{"1password-connect", "doppler"} {
		if got[provider+"/x509_certificate"] != 1 || got[provider+"/secret_store_api_key"] != 1 {
			t.Fatalf("inspected findings of %s = %v", provider, got)
		}
	}
	if bytes.Contains(body, []byte(apiKey)) || bytes.Contains(body, []byte("BEGIN CERTIFICATE")) {
		t.Fatal("the inspected findings carry a stored value")
	}
	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/cloud-secret-managers", o.tok, nil)
	var posture struct {
		Providers []struct {
			ID                   string `json:"id"`
			DiscoveryConfigured  bool   `json:"discovery_configured"`
			DiscoverySourceCount int    `json:"discovery_source_count"`
			SyncSupported        bool   `json:"sync_supported"`
		} `json:"providers"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &posture) != nil {
		t.Fatalf("posture = %d %s", status, raw)
	}
	seen := 0
	for _, p := range posture.Providers {
		if p.ID == "1password-connect" || p.ID == "doppler" {
			seen++
			if !p.DiscoveryConfigured || p.DiscoverySourceCount != 2 || p.SyncSupported {
				t.Fatalf("posture row %+v", p)
			}
		}
	}
	if seen != 2 {
		t.Fatalf("posture rows = %d (%s)", seen, raw)
	}
	t.Logf("OD14_STANDIN_OK")
}
