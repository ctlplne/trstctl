package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/cbom"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/profile"
)

type staticCBOMSource struct {
	name     string
	findings []cbom.Finding
}

func (s staticCBOMSource) Name() string { return s.name }

func (s staticCBOMSource) Scan(context.Context) ([]cbom.Finding, error) {
	return append([]cbom.Finding(nil), s.findings...), nil
}

// TestServedPQCMigrationReissuesCBOMAssetThroughACMEAndRollback is the PQC-06
// keystone: CBOM observes a classical RSA certificate-key estate, the served
// migration API enqueues the re-issue side effect through the real outbox, the
// dispatcher mints a hybrid ML-DSA transition certificate through the same served
// ACME/protocol issuance seam as PQC-04, and rollback restores the prior CBOM
// posture through an evented projection.
func TestServedPQCMigrationReissuesCBOMAssetThroughACMEAndRollback(t *testing.T) {
	const profileName = "pqc-migration-acme"
	h := newServedHarness(t,
		config.Protocols{ACME: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		func(d *Deps) { d.DefaultProfile = profileName; d.EnableRemediation = true },
	)
	storeServerTestProfile(t, h.store, h.tenant, profileName, profile.CertificateProfile{
		Name:                 profileName,
		AllowedKeyAlgorithms: []string{crypto.HybridMLDSA44ECDSAP256Algorithm},
		AllowedProtocols:     []string{"acme"},
		MaxValidity:          profile.Duration(30 * 24 * time.Hour),
	})

	scanner := cbom.NewScanner(&eventedCBOMSink{store: h.store, log: h.log, tenantID: h.tenant}, cbom.WithWorkers(1), cbom.WithQueue(1))
	defer scanner.Close()
	report := scanner.Scan(context.Background(), []cbom.Source{staticCBOMSource{
		name: "rsa-estate",
		findings: []cbom.Finding{{
			Kind:      cbom.AssetCertKey,
			Location:  "payments-rsa.internal:443",
			Algorithm: "RSA",
			KeyBits:   2048,
		}},
	}})
	if report.Findings != 1 || report.QuantumVulnerable != 1 || report.Failed != 0 {
		t.Fatalf("CBOM RSA source report = %+v, want one quantum-vulnerable finding", report)
	}

	tok := seedScopedToken(t, h.store, h.tenant, "risk:read", "certs:issue", "certs:read")
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/cbom/assets", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list CBOM assets before migration: status %d body %s", status, body)
	}
	var before struct {
		Items []struct {
			ID                string `json:"id"`
			Kind              string `json:"kind"`
			Algorithm         string `json:"algorithm"`
			QuantumVulnerable bool   `json:"quantum_vulnerable"`
			MigrationTarget   string `json:"migration_target"`
		} `json:"items"`
		MigrationProgress struct {
			TotalAssets             int     `json:"total_assets"`
			QuantumVulnerableAssets int     `json:"quantum_vulnerable_assets"`
			PercentMigrated         float64 `json:"percent_migrated"`
		} `json:"migration_progress"`
	}
	if err := json.Unmarshal(body, &before); err != nil {
		t.Fatalf("decode pre-migration inventory: %v (%s)", err, body)
	}
	if len(before.Items) != 1 {
		t.Fatalf("pre-migration inventory items = %d, want only the RSA estate item: %s", len(before.Items), body)
	}
	asset := before.Items[0]
	if asset.Kind != string(cbom.AssetCertKey) || asset.Algorithm != "RSA" || !asset.QuantumVulnerable || asset.MigrationTarget != "ML-DSA-65" {
		t.Fatalf("pre-migration asset = %+v, want RSA certificate-key mapped to ML-DSA-65", asset)
	}
	if before.MigrationProgress.TotalAssets != 1 || before.MigrationProgress.QuantumVulnerableAssets != 1 || before.MigrationProgress.PercentMigrated != 0 {
		t.Fatalf("pre-migration progress = %+v, want 0%% migrated", before.MigrationProgress)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/pqc/migrations", tok, "pqc-06-start", map[string]any{
		"asset_ids":           []string{asset.ID},
		"target_algorithm":    "ML-DSA-65",
		"protocol":            "acme",
		"rollback_on_failure": true,
	})
	if status != http.StatusAccepted {
		t.Fatalf("start PQC migration: status %d body %s", status, body)
	}
	var started struct {
		RunID              string `json:"run_id"`
		Queued             int    `json:"queued"`
		MigrationProgress  any    `json:"migration_progress"`
		RollbackConfigured bool   `json:"rollback_configured"`
	}
	if err := json.Unmarshal(body, &started); err != nil {
		t.Fatalf("decode migration start: %v (%s)", err, body)
	}
	if started.RunID == "" || started.Queued != 1 || !started.RollbackConfigured || started.MigrationProgress == nil {
		t.Fatalf("migration start response = %+v, want queued run with rollback and progress", started)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain PQC migration outbox: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/cbom/assets", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list CBOM assets after migration: status %d body %s", status, body)
	}
	var after struct {
		Items []struct {
			ID                  string `json:"id"`
			Algorithm           string `json:"algorithm"`
			QuantumVulnerable   bool   `json:"quantum_vulnerable"`
			MigrationGeneration string `json:"migration_generation"`
		} `json:"items"`
		MigrationProgress struct {
			TotalAssets             int     `json:"total_assets"`
			QuantumVulnerableAssets int     `json:"quantum_vulnerable_assets"`
			PostQuantumReadyAssets  int     `json:"post_quantum_ready_assets"`
			PercentMigrated         float64 `json:"percent_migrated"`
		} `json:"migration_progress"`
	}
	if err := json.Unmarshal(body, &after); err != nil {
		t.Fatalf("decode post-migration inventory: %v (%s)", err, body)
	}
	if len(after.Items) != 1 || after.Items[0].ID != asset.ID {
		t.Fatalf("post-migration inventory = %+v, want same asset id %s", after.Items, asset.ID)
	}
	if after.Items[0].Algorithm != crypto.HybridMLDSA44ECDSAP256Algorithm || after.Items[0].QuantumVulnerable || after.Items[0].MigrationGeneration != "post-quantum-ready" {
		t.Fatalf("post-migration asset = %+v, want hybrid ML-DSA transition key marked PQ-ready", after.Items[0])
	}
	if after.MigrationProgress.TotalAssets != 1 || after.MigrationProgress.QuantumVulnerableAssets != 0 ||
		after.MigrationProgress.PostQuantumReadyAssets != 1 || after.MigrationProgress.PercentMigrated != 100 {
		t.Fatalf("post-migration progress = %+v, want 100%% migrated", after.MigrationProgress)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/certificates", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list certificates after migration: status %d body %s", status, body)
	}
	var certs struct {
		Items []struct {
			KeyAlgorithm string `json:"key_algorithm"`
			Source       string `json:"source"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &certs); err != nil {
		t.Fatalf("decode migrated certificates: %v (%s)", err, body)
	}
	var sawHybridMigrationCert bool
	for _, cert := range certs.Items {
		if cert.KeyAlgorithm == crypto.HybridMLDSA44ECDSAP256Algorithm && cert.Source == "protocol:acme" {
			sawHybridMigrationCert = true
		}
	}
	if !sawHybridMigrationCert {
		t.Fatalf("no served ACME hybrid PQC migration certificate found: %+v", certs.Items)
	}
	if !h.hasEvent(t, "protocol.issued") || !h.hasEvent(t, "pqc.migration.asset_completed") {
		t.Fatal("missing served PQC migration issuance events")
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/pqc/migrations/"+started.RunID+"/rollback", tok, "pqc-06-rollback", map[string]any{
		"asset_ids": []string{asset.ID},
		"reason":    "acceptance rollback drill",
	})
	if status != http.StatusAccepted {
		t.Fatalf("rollback PQC migration: status %d body %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain PQC rollback outbox: %v", err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/cbom/assets", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list CBOM assets after rollback: status %d body %s", status, body)
	}
	var rolledBack struct {
		Items []struct {
			ID                string `json:"id"`
			Algorithm         string `json:"algorithm"`
			QuantumVulnerable bool   `json:"quantum_vulnerable"`
		} `json:"items"`
		MigrationProgress struct {
			QuantumVulnerableAssets int     `json:"quantum_vulnerable_assets"`
			PercentMigrated         float64 `json:"percent_migrated"`
		} `json:"migration_progress"`
	}
	if err := json.Unmarshal(body, &rolledBack); err != nil {
		t.Fatalf("decode rollback inventory: %v (%s)", err, body)
	}
	if len(rolledBack.Items) != 1 || rolledBack.Items[0].ID != asset.ID ||
		rolledBack.Items[0].Algorithm != "RSA" || !rolledBack.Items[0].QuantumVulnerable {
		t.Fatalf("rollback inventory = %+v, want original RSA quantum-vulnerable asset", rolledBack.Items)
	}
	if rolledBack.MigrationProgress.QuantumVulnerableAssets != 1 || rolledBack.MigrationProgress.PercentMigrated != 0 {
		t.Fatalf("rollback progress = %+v, want 0%% migrated", rolledBack.MigrationProgress)
	}
	if !h.hasEvent(t, "pqc.migration.rollback_completed") {
		t.Fatal("missing pqc.migration.rollback_completed event")
	}
}
