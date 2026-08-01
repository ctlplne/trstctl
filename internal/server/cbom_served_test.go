// SPDX-License-Identifier: MPL-2.0

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

	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:write", "risk:read")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/cbom/scans", tok, "licensed-crypto-cbom-scan", map[string]any{
		"tls_endpoints": []string{u.Host},
		"host_configs":  []string{conf},
	})
	if status != http.StatusCreated {
		t.Fatalf("start CBOM scan: status %d body %s", status, body)
	}
	var scan struct {
		Report struct {
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
	if scan.MigrationProgress.TotalAssets < 4 || scan.MigrationProgress.QuantumVulnerableAssets == 0 || scan.MigrationProgress.PercentMigrated >= 100 {
		t.Fatalf("scan migration progress = %+v, want partial/non-complete migration", scan.MigrationProgress)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/cbom/assets", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list CBOM assets: status %d body %s", status, body)
	}
	var inv struct {
		Items []struct {
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
