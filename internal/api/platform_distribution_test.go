// SPDX-License-Identifier: MPL-2.0

package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/api"
)

func TestServedPlatformDistributionCAPMODEL01(t *testing.T) {
	handler := api.New(nil, nil, nil, api.WithInsecureHeaderResolver())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform/distribution", nil)
	req.Header.Set("X-Tenant-ID", "11111111-1111-1111-1111-111111111111")
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("platform distribution status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got struct {
		Capability             string   `json:"capability"`
		Capabilities           []string `json:"capabilities"`
		Served                 bool     `json:"served"`
		ControlPlaneLineage    string   `json:"control_plane_lineage"`
		DefaultEvaluationMode  string   `json:"default_evaluation_mode"`
		ProductionMode         string   `json:"production_mode"`
		OfflineLicenseVerifier bool     `json:"offline_license_verifier"`
		CoreAuditAndExport     bool     `json:"core_audit_and_export"`
		RunModes               []struct {
			ID                 string   `json:"id"`
			PostgresMode       string   `json:"postgres_mode"`
			NATSMode           string   `json:"nats_mode"`
			SignerProcessModel string   `json:"signer_process_model"`
			EvidenceRefs       []string `json:"evidence_refs"`
		} `json:"run_modes"`
		SupportedHostArchives []struct {
			OSArch string `json:"os_arch"`
		} `json:"supported_host_archives"`
		AirGap struct {
			Capability                string   `json:"capability"`
			Served                    bool     `json:"served"`
			RuntimeEgressGuard        bool     `json:"runtime_egress_guard"`
			NoPhoneHomeDefault        bool     `json:"no_phone_home_default"`
			PublicTelemetryFailClosed bool     `json:"public_telemetry_fail_closed"`
			CloudAIFailClosed         bool     `json:"cloud_ai_fail_closed"`
			DataResidencyControls     []string `json:"data_residency_controls"`
			EvidenceRefs              []string `json:"evidence_refs"`
			BuyerEvidenceReceipts     []string `json:"buyer_evidence_receipts"`
		} `json:"air_gap"`
		ReleaseGates []string `json:"release_gates"`
		EvidenceRefs []string `json:"evidence_refs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode platform distribution: %v", err)
	}
	if got.Capability != "CAP-MODEL-01" || !got.Served {
		t.Fatalf("capability/served = %q/%v, want CAP-MODEL-01/true", got.Capability, got.Served)
	}
	if !containsString(got.Capabilities, "CAP-MODEL-01") || !containsString(got.Capabilities, "CAP-MODEL-03") {
		t.Fatalf("capabilities = %+v, want CAP-MODEL-01 and CAP-MODEL-03", got.Capabilities)
	}
	if got.ControlPlaneLineage == "" || got.DefaultEvaluationMode == "" || got.ProductionMode == "" {
		t.Fatalf("distribution posture missing buyer-facing lineage or run modes: %+v", got)
	}
	if !got.OfflineLicenseVerifier || !got.CoreAuditAndExport {
		t.Fatalf("open-core posture must keep offline license verification and audit/export in core: %+v", got)
	}
	requirePlatformRunMode(t, got.RunModes, "host-archive-eval", "bundled", "embedded")
	requirePlatformRunMode(t, got.RunModes, "external-production", "external", "external")
	requirePlatformRunMode(t, got.RunModes, "kubernetes-helm", "external", "external")
	requirePlatformArchive(t, got.SupportedHostArchives, "linux-amd64")
	requirePlatformArchive(t, got.SupportedHostArchives, "linux-arm64v8")
	requirePlatformArchive(t, got.SupportedHostArchives, "darwin-arm64v8")
	for _, want := range []string{"make lint test", "embedded-postgres scan receipts", "architecture linter"} {
		if !containsString(got.ReleaseGates, want) {
			t.Fatalf("release gates missing %q in %+v", want, got.ReleaseGates)
		}
	}
	for _, want := range []string{"deploy/supply-chain/embedded-postgres.json", "internal/server/startBundledPostgres", "docs/features/platform-and-api.md"} {
		if !containsString(got.EvidenceRefs, want) {
			t.Fatalf("evidence refs missing %q in %+v", want, got.EvidenceRefs)
		}
	}
	if got.AirGap.Capability != "CAP-MODEL-03" || !got.AirGap.Served {
		t.Fatalf("air-gap capability/served = %q/%v, want CAP-MODEL-03/true", got.AirGap.Capability, got.AirGap.Served)
	}
	if !got.AirGap.RuntimeEgressGuard || !got.AirGap.NoPhoneHomeDefault || !got.AirGap.PublicTelemetryFailClosed || !got.AirGap.CloudAIFailClosed {
		t.Fatalf("air-gap fail-closed controls missing: %+v", got.AirGap)
	}
	for _, want := range []string{"TRSTCTL_AIRGAP_ENABLED", "values-airgap.yaml"} {
		if !containsString(got.AirGap.DataResidencyControls, want) {
			t.Fatalf("air-gap data-residency controls missing %q in %+v", want, got.AirGap.DataResidencyControls)
		}
	}
	for _, want := range []string{"docs/airgap.md", "internal/server/airgap_served_test.go", "deploy/helm/trstctl/values-airgap.yaml"} {
		if !containsString(got.AirGap.EvidenceRefs, want) {
			t.Fatalf("air-gap evidence refs missing %q in %+v", want, got.AirGap.EvidenceRefs)
		}
	}
	for _, want := range []string{"GET /api/v1/platform/distribution", "trstctl-cli platform distribution", "docs/airgap.md"} {
		if !containsString(got.AirGap.BuyerEvidenceReceipts, want) {
			t.Fatalf("air-gap buyer receipts missing %q in %+v", want, got.AirGap.BuyerEvidenceReceipts)
		}
	}
}

func requirePlatformRunMode(t *testing.T, modes []struct {
	ID                 string   `json:"id"`
	PostgresMode       string   `json:"postgres_mode"`
	NATSMode           string   `json:"nats_mode"`
	SignerProcessModel string   `json:"signer_process_model"`
	EvidenceRefs       []string `json:"evidence_refs"`
}, id, postgresMode, natsMode string) {
	t.Helper()
	for _, mode := range modes {
		if mode.ID == id {
			if mode.PostgresMode != postgresMode || mode.NATSMode != natsMode {
				t.Fatalf("run mode %s datastore modes = %s/%s, want %s/%s", id, mode.PostgresMode, mode.NATSMode, postgresMode, natsMode)
			}
			if mode.SignerProcessModel == "" || len(mode.EvidenceRefs) == 0 {
				t.Fatalf("run mode %s missing signer or evidence posture: %+v", id, mode)
			}
			return
		}
	}
	t.Fatalf("missing run mode %s in %+v", id, modes)
}

func requirePlatformArchive(t *testing.T, archives []struct {
	OSArch string `json:"os_arch"`
}, osArch string) {
	t.Helper()
	for _, archive := range archives {
		if archive.OSArch == osArch {
			return
		}
	}
	t.Fatalf("missing host archive %s in %+v", osArch, archives)
}
