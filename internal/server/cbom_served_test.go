// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestRetryCBOMWriteRetriesTransientFailure(t *testing.T) {
	attempts := 0
	err := retryCBOMWrite(context.Background(), func() error {
		attempts++
		if attempts < cbomWriteAttempts {
			return errors.New("transient write failure")
		}
		return nil
	})
	if err != nil || attempts != cbomWriteAttempts {
		t.Fatalf("retry result err=%v attempts=%d, want success on attempt %d", err, attempts, cbomWriteAttempts)
	}
}

func TestRetryCBOMWriteStopsOnCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	attempts := 0
	err := retryCBOMWrite(ctx, func() error {
		attempts++
		return context.Canceled
	})
	if !errors.Is(err, context.Canceled) || attempts != 1 {
		t.Fatalf("retry result err=%v attempts=%d, want immediate cancellation", err, attempts)
	}
}

func TestServedCBOMRescanRetiresReplacedHostFacts(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "discovery:write", "risk:read")
	path := filepath.Join(t.TempDir(), "tls.conf")
	scan := func(key string, wantFailed int, paths ...string) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/cbom/scans", token, map[string]any{
			"host_configs": paths,
		})
		if status != http.StatusCreated {
			t.Fatalf("%s scan: status %d body %s", key, status, body)
		}
		var result struct {
			Report struct {
				Failed int `json:"failed"`
			} `json:"report"`
		}
		if err := json.Unmarshal(body, &result); err != nil || result.Report.Failed != wantFailed {
			t.Fatalf("%s scan report = %+v, decode = %v", key, result, err)
		}
	}
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("ssl_protocols TLSv1;\nssl_ciphers TLS_RSA_WITH_3DES_EDE_CBC_SHA;\n")
	scan("weak", 0, path)
	write("ssl_protocols TLSv1.3;\nssl_ciphers TLS_AES_256_GCM_SHA384;\n")
	// One unreadable selector makes the request incomplete. Its new strong facts
	// are useful, but prior weak facts remain active until a complete rescan.
	scan("partial", 1, path, filepath.Join(t.TempDir(), "missing.conf"))
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/cbom/assets", token, nil)
	if status != http.StatusOK {
		t.Fatalf("partial inventory: status %d body %s", status, body)
	}
	if !json.Valid(body) || !containsCBOMWeakFact(body, path) {
		t.Fatalf("partial scan falsely cleared old risk: %s", body)
	}
	scan("strong", 0, path)
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/cbom/assets", token, nil)
	if status != http.StatusOK {
		t.Fatalf("inventory: status %d body %s", status, body)
	}
	var inventory struct {
		Items []struct {
			Location    string `json:"location"`
			Protocol    string `json:"protocol"`
			Cipher      string `json:"cipher"`
			OutOfPolicy bool   `json:"out_of_policy"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &inventory); err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, item := range inventory.Items {
		if item.Location != path {
			continue
		}
		seen++
		if item.OutOfPolicy || item.Protocol == "TLSv1.0" || item.Cipher == "TLS_RSA_WITH_3DES_EDE_CBC_SHA" {
			t.Errorf("retired weak fact still active after clean rescan: %+v", item)
		}
	}
	if seen != 2 {
		t.Errorf("active facts at source = %d, want exact strong protocol and cipher", seen)
	}
}

func containsCBOMWeakFact(body []byte, path string) bool {
	var inventory struct {
		Items []struct {
			Location string `json:"location"`
			Protocol string `json:"protocol"`
		} `json:"items"`
	}
	if json.Unmarshal(body, &inventory) != nil {
		return false
	}
	for _, item := range inventory.Items {
		if item.Location == path && item.Protocol == "TLSv1.0" {
			return true
		}
	}
	return false
}

// TestServedCBOMScanPopulatesMigrationInventory verifies that the
// assembled control plane drives a real served CBOM scan over a fixture TLS estate
// and host config, records observations through the AN-2 event log, projects them
// into crypto_assets, and exposes customer-readable migration guidance and progress.
func TestServedCBOMScanPopulatesMigrationInventory(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(tlsSrv.Close)
	u, err := url.Parse(tlsSrv.URL)
	if err != nil {
		t.Fatalf("parse test TLS URL: %v", err)
	}

	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("ssl_protocols TLSv1 TLSv1.2;\nssl_ciphers DES-CBC3-SHA:ECDHE-RSA-AES128-GCM-SHA256;\n"), 0o644); err != nil { // #nosec G306 -- fixture file in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatalf("write host crypto fixture: %v", err)
	}

	h := newOperatingServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:write", "risk:read")
	beforePreview, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatalf("read event head before preview: %v", err)
	}

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/cbom/scans/preview", tok, map[string]any{
		"tls_endpoints": []string{tlsSrv.URL, u.Host},
		"host_configs":  []string{conf, conf},
	})
	if status != http.StatusOK {
		t.Fatalf("preview CBOM scan: status %d body %s", status, body)
	}
	var preview struct {
		Capability        string `json:"capability"`
		Ready             bool   `json:"ready"`
		EffectFree        bool   `json:"effect_free"`
		NormalizedRequest struct {
			TLSEndpoints []string `json:"tls_endpoints"`
			HostConfigs  []string `json:"host_configs"`
		} `json:"normalized_request"`
		TLSConnectionLimit int      `json:"tls_connection_limit"`
		HostFileReadLimit  int      `json:"host_file_read_limit"`
		HostFileByteLimit  int64    `json:"host_file_byte_limit"`
		FindingWriteLimit  int      `json:"finding_write_limit"`
		WorkerLimit        int      `json:"worker_limit"`
		QueueDepth         int      `json:"queue_depth"`
		SignerCalls        int      `json:"signer_calls"`
		OutboxCalls        int      `json:"outbox_calls"`
		RecoverySteps      []string `json:"recovery_steps"`
	}
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatalf("decode CBOM preview: %v (%s)", err, body)
	}
	if preview.Capability != "F52" || !preview.Ready || !preview.EffectFree ||
		len(preview.NormalizedRequest.TLSEndpoints) != 1 || preview.NormalizedRequest.TLSEndpoints[0] != u.Host ||
		len(preview.NormalizedRequest.HostConfigs) != 1 || preview.NormalizedRequest.HostConfigs[0] != conf ||
		preview.TLSConnectionLimit != 1 || preview.HostFileReadLimit != 256 || preview.HostFileByteLimit != 1<<20 ||
		preview.FindingWriteLimit != 1026 || preview.WorkerLimit != 4 || preview.QueueDepth != 64 ||
		preview.SignerCalls != 0 || preview.OutboxCalls != 0 || len(preview.RecoverySteps) < 3 {
		t.Fatalf("CBOM preview does not state the exact safe plan: %+v body=%s", preview, body)
	}
	if afterPreview, lastErr := h.log.LastSequence(t.Context()); lastErr != nil || afterPreview != beforePreview {
		t.Fatalf("preview event head=(%d,%v), want unchanged %d", afterPreview, lastErr, beforePreview)
	}
	assetsBefore, err := h.store.ListCryptoAssets(t.Context(), h.tenant)
	if err != nil || len(assetsBefore) != 0 {
		t.Fatalf("preview crypto assets=(%d,%v), want no writes", len(assetsBefore), err)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/cbom/scans/preview", tok, map[string]any{
		"tls_endpoints": []string{"https://example.com/private/path"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("invalid-scope preview: status %d body %s", status, body)
	}
	if afterInvalid, lastErr := h.log.LastSequence(t.Context()); lastErr != nil || afterInvalid != beforePreview {
		t.Fatalf("invalid preview event head=(%d,%v), want unchanged %d", afterInvalid, lastErr, beforePreview)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/cbom/scans", tok, "licensed-crypto-cbom-scan", map[string]any{
		"tls_endpoints": []string{u.Host},
		"host_configs":  []string{conf},
	})
	if status != http.StatusCreated {
		t.Fatalf("start CBOM scan: status %d body %s", status, body)
	}
	var scan struct {
		ObservedAssetIDs []string `json:"observed_asset_ids"`
		Report           struct {
			Findings          int `json:"findings"`
			QuantumVulnerable int `json:"quantum_vulnerable"`
			OutOfPolicy       int `json:"out_of_policy"`
		} `json:"report"`
		MigrationProgress struct {
			TotalAssets             int     `json:"total_assets"`
			QuantumVulnerableAssets int     `json:"quantum_vulnerable_assets"`
			PercentMigrated         float64 `json:"percent_migrated"`
		} `json:"migration_progress"`
	}
	if err := json.Unmarshal(body, &scan); err != nil {
		t.Fatalf("decode CBOM scan response: %v (%s)", err, body)
	}
	if scan.Report.Findings < 4 || scan.Report.QuantumVulnerable == 0 || scan.Report.OutOfPolicy == 0 {
		t.Fatalf("scan report = %+v, want TLS + host findings with quantum and policy gaps", scan.Report)
	}
	if len(scan.ObservedAssetIDs) < 4 {
		t.Fatalf("scan observed IDs = %v, want exact durable IDs for TLS and host observations", scan.ObservedAssetIDs)
	}
	if scan.MigrationProgress.TotalAssets < 4 || scan.MigrationProgress.QuantumVulnerableAssets == 0 || scan.MigrationProgress.PercentMigrated >= 100 {
		t.Fatalf("scan migration progress = %+v, want partial/non-complete migration", scan.MigrationProgress)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/cbom/assets", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list CBOM assets: status %d body %s", status, body)
	}
	var inv struct {
		Items []struct {
			ID                  string `json:"id"`
			Kind                string `json:"kind"`
			Location            string `json:"location"`
			Algorithm           string `json:"algorithm"`
			Protocol            string `json:"protocol"`
			Cipher              string `json:"cipher"`
			QuantumVulnerable   bool   `json:"quantum_vulnerable"`
			OutOfPolicy         bool   `json:"out_of_policy"`
			MigrationTarget     string `json:"migration_target"`
			MigrationStandard   string `json:"migration_standard"`
			MigrationGeneration string `json:"migration_generation"`
		} `json:"items"`
		MigrationProgress struct {
			TotalAssets             int     `json:"total_assets"`
			QuantumVulnerableAssets int     `json:"quantum_vulnerable_assets"`
			PercentMigrated         float64 `json:"percent_migrated"`
		} `json:"migration_progress"`
	}
	if err := json.Unmarshal(body, &inv); err != nil {
		t.Fatalf("decode CBOM inventory: %v (%s)", err, body)
	}
	if len(inv.Items) < 4 {
		t.Fatalf("CBOM inventory has %d assets, want TLS endpoint/key plus host protocol/cipher: %s", len(inv.Items), body)
	}
	observed := make(map[string]bool, len(scan.ObservedAssetIDs))
	for _, id := range scan.ObservedAssetIDs {
		observed[id] = false
	}
	for _, item := range inv.Items {
		if _, ok := observed[item.ID]; ok {
			observed[item.ID] = true
		}
	}
	for id, found := range observed {
		if !found {
			t.Fatalf("scan asset %s absent from independent tenant inventory", id)
		}
	}
	var sawSignatureReplacement, sawTLSReplacement, sawWeakConfig bool
	for _, item := range inv.Items {
		switch {
		case item.Algorithm == "RSA" || item.Algorithm == "ECDSA" || item.Algorithm == "Ed25519":
			sawSignatureReplacement = item.QuantumVulnerable &&
				item.MigrationTarget == "licensed-signature-transition" &&
				item.MigrationStandard == "licensed"
		case item.Protocol == "TLSv1.2" || item.Protocol == "TLSv1.3":
			sawTLSReplacement = item.MigrationTarget == "licensed-key-establishment-transition" &&
				item.MigrationStandard == "licensed"
		case item.Protocol == "TLSv1.0" || item.Cipher == "DES-CBC3-SHA":
			sawWeakConfig = item.OutOfPolicy && item.MigrationTarget != ""
		}
		if item.MigrationGeneration == "" {
			t.Fatalf("inventory item has no migration generation: %+v", item)
		}
	}
	if !sawSignatureReplacement {
		t.Fatalf("no classical certificate-key asset mapped to a licensed signature transition: %+v", inv.Items)
	}
	if !sawTLSReplacement {
		t.Fatalf("no TLS endpoint mapped to a licensed key-establishment transition: %+v", inv.Items)
	}
	if !sawWeakConfig {
		t.Fatalf("no weak host config mapped to a migration target: %+v", inv.Items)
	}
	if inv.MigrationProgress.TotalAssets != len(inv.Items) || inv.MigrationProgress.PercentMigrated >= 100 {
		t.Fatalf("inventory migration progress = %+v for %d items", inv.MigrationProgress, len(inv.Items))
	}

	assets, err := h.store.ListCryptoAssets(context.Background(), h.tenant)
	if err != nil {
		t.Fatalf("list stored crypto assets: %v", err)
	}
	if len(assets) != len(inv.Items) {
		t.Fatalf("stored crypto_assets = %d, served inventory items = %d", len(assets), len(inv.Items))
	}
	if !h.hasEvent(t, "cbom.asset.observed") {
		t.Fatal("missing cbom.asset.observed event; served CBOM scan is not event-sourced")
	}
}
