package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// TestServedDiscoveryNetworkScanEndToEnd is the JOURNEY-001 proof: the assembled
// control plane serves discovery source/run/finding APIs, queues scan execution
// through the outbox, records findings through projected events, and feeds the
// certificate inventory. On the pre-wiring tree the first POST is a 404 because
// discovery existed only as library code.
func TestServedDiscoveryNetworkScanEndToEnd(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(tlsSrv.Close)
	u, err := url.Parse(tlsSrv.URL)
	if err != nil {
		t.Fatalf("parse test TLS URL: %v", err)
	}

	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "certs:read")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "loopback-tls",
		"kind": "network",
		"config": map[string]any{
			"targets":        []string{u.Host},
			"allow_loopback": true,
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create discovery source: status %d body %s", status, body)
	}
	var source struct {
		ID       string          `json:"id"`
		TenantID string          `json:"tenant_id"`
		Kind     string          `json:"kind"`
		Config   json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatalf("decode source: %v (%s)", err, body)
	}
	if source.ID == "" || source.TenantID != h.tenant || source.Kind != "network" {
		t.Fatalf("bad source response: %+v", source)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{
		"source_id": source.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("start discovery run: status %d body %s", status, body)
	}
	var queued struct {
		ID       string `json:"id"`
		Status   string `json:"status"`
		SourceID string `json:"source_id"`
	}
	if err := json.Unmarshal(body, &queued); err != nil {
		t.Fatalf("decode queued run: %v (%s)", err, body)
	}
	if queued.ID == "" || queued.SourceID != source.ID || queued.Status != "queued" {
		t.Fatalf("bad queued run: %+v", queued)
	}

	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain discovery outbox: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get discovery run: status %d body %s", status, body)
	}
	var completed struct {
		Status     string `json:"status"`
		Targets    int    `json:"targets"`
		Discovered int    `json:"discovered"`
		Failed     int    `json:"failed"`
	}
	if err := json.Unmarshal(body, &completed); err != nil {
		t.Fatalf("decode completed run: %v (%s)", err, body)
	}
	if completed.Status != "succeeded" || completed.Targets != 1 || completed.Discovered != 1 || completed.Failed != 0 {
		t.Fatalf("completed run = %+v, want one successful discovery", completed)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list discovery findings: status %d body %s", status, body)
	}
	var findings struct {
		Items []struct {
			Kind        string `json:"kind"`
			Ref         string `json:"ref"`
			Provenance  string `json:"provenance"`
			Fingerprint string `json:"fingerprint"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &findings); err != nil {
		t.Fatalf("decode findings: %v (%s)", err, body)
	}
	if len(findings.Items) != 1 {
		t.Fatalf("findings count = %d body %s, want 1", len(findings.Items), body)
	}
	if f := findings.Items[0]; f.Kind != "x509_certificate" || f.Ref != u.Host || f.Fingerprint == "" || !strings.Contains(f.Provenance, "network") {
		t.Fatalf("bad finding: %+v", f)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/certificates", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list certificates: status %d body %s", status, body)
	}
	var certs struct {
		Items []struct {
			DeploymentLocation string `json:"deployment_location"`
			Source             string `json:"source"`
			Fingerprint        string `json:"fingerprint"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &certs); err != nil {
		t.Fatalf("decode certificates: %v (%s)", err, body)
	}
	if len(certs.Items) != 1 || certs.Items[0].DeploymentLocation != u.Host || certs.Items[0].Source != "discovery:network" || certs.Items[0].Fingerprint == "" {
		t.Fatalf("inventory was not populated from discovery: %+v", certs.Items)
	}

	for _, eventType := range []string{"discovery.source.upserted", "discovery.run.queued", "discovery.finding.recorded", "certificate.recorded"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing %s event; discovery is not fully event-sourced", eventType)
		}
	}
}

func TestServedContinuousMonitoringCentralizedInventoryCAPDISC06(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(tlsSrv.Close)
	u, err := url.Parse(tlsSrv.URL)
	if err != nil {
		t.Fatalf("parse test TLS URL: %v", err)
	}

	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "certs:read")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "loopback-continuous",
		"kind": "network",
		"config": map[string]any{
			"targets":        []string{u.Host},
			"allow_loopback": true,
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create discovery source: status %d body %s", status, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatalf("decode source: %v (%s)", err, body)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/schedules", tok, map[string]any{
		"source_id":        source.ID,
		"name":             "loopback-continuous-every-5m",
		"interval_seconds": 300,
		"enabled":          true,
	})
	if status != http.StatusCreated {
		t.Fatalf("create discovery schedule: status %d body %s", status, body)
	}
	var schedule struct {
		ID              string `json:"id"`
		IntervalSeconds int    `json:"interval_seconds"`
		Enabled         bool   `json:"enabled"`
	}
	if err := json.Unmarshal(body, &schedule); err != nil {
		t.Fatalf("decode schedule: %v (%s)", err, body)
	}
	if schedule.ID == "" || schedule.IntervalSeconds != 300 || !schedule.Enabled {
		t.Fatalf("bad schedule: %+v", schedule)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{
		"source_id":   source.ID,
		"schedule_id": schedule.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("start scheduled discovery run: status %d body %s", status, body)
	}
	var queued struct {
		ID         string  `json:"id"`
		SourceID   string  `json:"source_id"`
		ScheduleID *string `json:"schedule_id"`
		Status     string  `json:"status"`
	}
	if err := json.Unmarshal(body, &queued); err != nil {
		t.Fatalf("decode queued run: %v (%s)", err, body)
	}
	if queued.ID == "" || queued.SourceID != source.ID || queued.ScheduleID == nil || *queued.ScheduleID != schedule.ID || queued.Status != "queued" {
		t.Fatalf("bad queued scheduled run: %+v", queued)
	}

	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain scheduled discovery outbox: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/monitoring", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("continuous monitoring inventory = %d body %s, want 200", status, body)
	}
	var got struct {
		RepositoryPath string `json:"repository_path"`
		FindingsPath   string `json:"findings_path"`
		Summary        struct {
			SourceCount               int `json:"source_count"`
			ScheduledSourceCount      int `json:"scheduled_source_count"`
			ActiveMonitoringCount     int `json:"active_monitoring_count"`
			RunCount                  int `json:"run_count"`
			CompletedRunCount         int `json:"completed_run_count"`
			FindingCount              int `json:"finding_count"`
			CertificateInventoryCount int `json:"certificate_inventory_count"`
		} `json:"summary"`
		Sources []struct {
			SourceID                  string `json:"source_id"`
			Kind                      string `json:"kind"`
			Name                      string `json:"name"`
			Scheduled                 bool   `json:"scheduled"`
			ScheduleID                string `json:"schedule_id"`
			MonitoringIntervalSeconds int    `json:"monitoring_interval_seconds"`
			LastRunID                 string `json:"last_run_id"`
			LastRunStatus             string `json:"last_run_status"`
			FindingCount              int    `json:"finding_count"`
			CertificateInventoryCount int    `json:"certificate_inventory_count"`
			RepositoryPath            string `json:"repository_path"`
			FindingsPath              string `json:"findings_path"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode monitoring inventory: %v (%s)", err, body)
	}
	if got.RepositoryPath != "/api/v1/certificates" || got.FindingsPath != "/api/v1/discovery/findings" {
		t.Fatalf("bad repository paths: %+v", got)
	}
	if got.Summary.SourceCount != 1 || got.Summary.ScheduledSourceCount != 1 || got.Summary.ActiveMonitoringCount != 1 ||
		got.Summary.RunCount != 1 || got.Summary.CompletedRunCount != 1 || got.Summary.FindingCount != 1 ||
		got.Summary.CertificateInventoryCount != 1 {
		t.Fatalf("bad monitoring summary: %+v", got.Summary)
	}
	if len(got.Sources) != 1 {
		t.Fatalf("monitoring source count = %d body %s, want 1", len(got.Sources), body)
	}
	row := got.Sources[0]
	if row.SourceID != source.ID || row.Kind != "network" || row.Name != "loopback-continuous" || !row.Scheduled ||
		row.ScheduleID != schedule.ID || row.MonitoringIntervalSeconds != 300 || row.LastRunID != queued.ID ||
		row.LastRunStatus != "succeeded" || row.FindingCount != 1 || row.CertificateInventoryCount != 1 ||
		row.RepositoryPath != "/api/v1/certificates" || !strings.Contains(row.FindingsPath, queued.ID) {
		t.Fatalf("bad monitoring source row: %+v", row)
	}
}

func TestServedEstateWideCertificateExpiryHealthCAPDISC07(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(tlsSrv.Close)
	u, err := url.Parse(tlsSrv.URL)
	if err != nil {
		t.Fatalf("parse test TLS URL: %v", err)
	}

	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write", "discovery:read", "discovery:write")

	importedPEM := servedHealthLeafPEM(t, h, "imported-edge.example", 48*time.Hour)
	issuedPEM := servedHealthLeafPEM(t, h, "issued-api.example", 15*24*time.Hour)
	ingestServedHealthCertificate(t, h, tok, "cap-disc-07-imported", importedPEM, "import", "f5:/Common/imported-edge")
	ingestServedHealthCertificate(t, h, tok, "cap-disc-07-issued", issuedPEM, "issued", "k8s:default/issued-api")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "loopback-health",
		"kind": "network",
		"config": map[string]any{
			"targets":        []string{u.Host},
			"allow_loopback": true,
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create health discovery source: status %d body %s", status, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatalf("decode health source: %v (%s)", err, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{"source_id": source.ID})
	if status != http.StatusCreated {
		t.Fatalf("start health discovery run: status %d body %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain health discovery outbox: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/certificates/health", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get certificate health: status %d body %s", status, body)
	}
	var health struct {
		InventoryPath string `json:"inventory_path"`
		ExpiringPath  string `json:"expiring_path"`
		Summary       struct {
			Total               int    `json:"total"`
			Expiring7d          int    `json:"expiring_7d"`
			Expiring30d         int    `json:"expiring_30d"`
			ExternalSourceCount int    `json:"external_source_count"`
			ImportedCount       int    `json:"imported_count"`
			DiscoveredCount     int    `json:"discovered_count"`
			Health              string `json:"health"`
		} `json:"summary"`
		SourceBreakdown []struct {
			Source      string `json:"source"`
			Count       int    `json:"count"`
			External    bool   `json:"external"`
			Expiring30d int    `json:"expiring_30d"`
		} `json:"source_breakdown"`
		Expiring []struct {
			Subject          string `json:"subject"`
			Source           string `json:"source"`
			DaysRemaining    int    `json:"days_remaining"`
			ExternallyIssued bool   `json:"externally_issued"`
		} `json:"expiring"`
	}
	if err := json.Unmarshal(body, &health); err != nil {
		t.Fatalf("decode certificate health: %v (%s)", err, body)
	}
	if health.InventoryPath != "/api/v1/certificates" || !strings.HasPrefix(health.ExpiringPath, "/api/v1/certificates?expiring_before=") {
		t.Fatalf("health paths do not point back to served inventory: %+v", health)
	}
	if health.Summary.Total < 3 || health.Summary.Expiring7d < 1 || health.Summary.Expiring30d < 2 {
		t.Fatalf("health summary missed estate-wide expiry counts: %+v", health.Summary)
	}
	if health.Summary.ExternalSourceCount < 2 || health.Summary.ImportedCount < 1 || health.Summary.DiscoveredCount < 1 {
		t.Fatalf("health summary did not include imported/discovered external certs: %+v", health.Summary)
	}
	if health.Summary.Health == "" || health.Summary.Health == "ok" {
		t.Fatalf("health should flag the near-expiry estate, got %+v", health.Summary)
	}
	seen := map[string]bool{}
	for _, row := range health.SourceBreakdown {
		seen[row.Source] = true
		if (row.Source == "import" || strings.HasPrefix(row.Source, "discovery:")) && (!row.External || row.Count == 0) {
			t.Fatalf("external source row not marked external: %+v", row)
		}
	}
	for _, source := range []string{"issued", "import", "discovery:network"} {
		if !seen[source] {
			t.Fatalf("health source breakdown missing %q in %+v", source, health.SourceBreakdown)
		}
	}
	foundExternalSoon := false
	for _, item := range health.Expiring {
		if item.Source == "import" && item.ExternallyIssued && item.DaysRemaining <= 2 {
			foundExternalSoon = true
		}
	}
	if !foundExternalSoon {
		t.Fatalf("health expiring list did not surface the near-expiry imported certificate: %+v", health.Expiring)
	}
}

func TestServedDiscoveryNetworkScanBlocksReservedTargets(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "blocked-network-targets",
		"kind": "network",
		"config": map[string]any{
			"targets": []string{
				"127.0.0.1:443",
				"169.254.169.254:443",
				"10.0.0.0:443",
			},
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create discovery source: status %d body %s", status, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatalf("decode source: %v", err)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{
		"source_id": source.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("start discovery run: status %d body %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain discovery outbox: %v", err)
	}
	if !h.hasEvent(t, "discovery.network_target_blocked") {
		t.Fatal("reserved network targets were not emitted as blocked-target events")
	}
}

// TestServedCrossSurfaceNHIDiscoveryCAPNHI01EndToEnd is the COMPETE-001 proof:
// CAP-NHI-01 is served through the same tenant-scoped discovery source/run/finding
// path as certificate discovery, but for metadata-only non-human identity
// observations across IdP, cloud, SaaS, on-prem, code, and CI surfaces.
func TestServedCrossSurfaceNHIDiscoveryCAPNHI01EndToEnd(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "nhi-cross-surface",
		"kind": "nhi_cross_surface",
		"config": map[string]any{
			"observations": []map[string]any{
				{"surface": "idp", "system": "okta", "external_id": "app/payments", "principal": "payments-api", "owner": "platform", "credential_kind": "oauth_client", "scopes": []string{"payments.read"}},
				{"surface": "cloud", "system": "aws-iam", "external_id": "role/payments-prod", "principal": "arn:aws:iam::111111111111:role/payments-prod", "owner": "platform", "credential_kind": "role"},
				{"surface": "saas", "system": "github", "external_id": "app/installations/42", "principal": "payments-ci-app", "owner": "devex", "credential_kind": "github_app"},
				{"surface": "on_prem", "system": "ldap", "external_id": "svc-payments", "principal": "svc-payments", "owner": "identity", "credential_kind": "service_account"},
				{"surface": "code", "system": "github-code-search", "external_id": "repo/payments/path/deploy.yaml", "principal": "payments-deploy-key", "owner": "devex", "credential_kind": "deploy_key"},
				{"surface": "ci", "system": "github-actions", "external_id": "repo/payments/env/prod", "principal": "payments-ci-token", "owner": "devex", "credential_kind": "workflow_identity"},
			},
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create cross-surface NHI source: status %d body %s", status, body)
	}
	var source struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatalf("decode source: %v (%s)", err, body)
	}
	if source.ID == "" || source.Kind != "nhi_cross_surface" {
		t.Fatalf("bad NHI source response: %+v", source)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{
		"source_id": source.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("start cross-surface NHI run: status %d body %s", status, body)
	}
	var queued struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &queued); err != nil {
		t.Fatalf("decode queued run: %v (%s)", err, body)
	}
	if queued.ID == "" || queued.Status != "queued" {
		t.Fatalf("bad queued run: %+v", queued)
	}

	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain NHI discovery outbox: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get cross-surface NHI run: status %d body %s", status, body)
	}
	var completed struct {
		Status     string `json:"status"`
		Targets    int    `json:"targets"`
		Discovered int    `json:"discovered"`
		Failed     int    `json:"failed"`
	}
	if err := json.Unmarshal(body, &completed); err != nil {
		t.Fatalf("decode completed run: %v (%s)", err, body)
	}
	if completed.Status != "succeeded" || completed.Targets != 6 || completed.Discovered != 6 || completed.Failed != 0 {
		t.Fatalf("completed run = %+v, want six successful NHI observations", completed)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list NHI discovery findings: status %d body %s", status, body)
	}
	var findings struct {
		Items []struct {
			Kind        string         `json:"kind"`
			Ref         string         `json:"ref"`
			Provenance  string         `json:"provenance"`
			Fingerprint string         `json:"fingerprint"`
			RiskScore   int            `json:"risk_score"`
			Metadata    map[string]any `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &findings); err != nil {
		t.Fatalf("decode NHI findings: %v (%s)", err, body)
	}
	if len(findings.Items) != 6 {
		t.Fatalf("findings count = %d body %s, want 6", len(findings.Items), body)
	}
	surfaces := map[string]bool{}
	for _, f := range findings.Items {
		if f.Kind != "non_human_identity" || f.Ref == "" || f.Fingerprint == "" || !strings.HasPrefix(f.Provenance, "nhi_cross_surface:") {
			t.Fatalf("bad NHI finding: %+v", f)
		}
		if f.RiskScore <= 0 {
			t.Fatalf("NHI finding should carry risk score: %+v", f)
		}
		surface, _ := f.Metadata["surface"].(string)
		surfaces[surface] = true
	}
	for _, surface := range []string{"idp", "cloud", "saas", "on_prem", "code", "ci"} {
		if !surfaces[surface] {
			t.Fatalf("surface %q was not represented in findings: %+v", surface, surfaces)
		}
	}
	if strings.Contains(string(body), "raw-value") || strings.Contains(string(body), "client_secret") {
		t.Fatalf("NHI discovery findings leaked inline credential material: %s", body)
	}

	for _, eventType := range []string{"discovery.source.upserted", "discovery.run.queued", "discovery.finding.recorded", "discovery.run.completed"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing %s event; NHI discovery is not fully event-sourced", eventType)
		}
	}
}

// TestServedUnifiedNHIInventoryCAPNHI02EndToEnd is the COMPETE-030 proof:
// CAP-NHI-02 is not just an identities-page rollup. The served inventory API
// must merge first-party identities/certificates/API tokens with metadata-only
// cross-surface findings for service accounts, API keys, OAuth apps, tokens/PATs,
// secrets, IAM roles, SSH keys, webhooks, and workload IDs.
func TestServedUnifiedNHIInventoryCAPNHI02EndToEnd(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:write", "identities:write", "certs:issue", "certs:read",
		"access:write", "access:read", "discovery:read", "discovery:write",
		"nhi:read",
	)

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{
		"kind": "workload",
		"name": "cap-nhi-02-owner",
	})
	if status != http.StatusCreated {
		t.Fatalf("create owner: status %d body %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatalf("decode owner: %v (%s)", err, body)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
		"kind":     "x509_certificate",
		"name":     "cap-nhi-02.served.test",
		"owner_id": owner.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("create certificate identity: status %d body %s", status, body)
	}
	var identity struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &identity); err != nil {
		t.Fatalf("decode identity: %v (%s)", err, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+identity.ID+"/transitions", tok, map[string]any{
		"to":     "issued",
		"reason": "CAP-NHI-02 issued certificate inventory seed",
	})
	if status != http.StatusOK {
		t.Fatalf("issue certificate identity: status %d body %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain certificate issuance: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/access/api-tokens", tok, map[string]any{
		"subject": "ci-personal-access-token",
		"scopes":  []string{"certs:read"},
	})
	if status != http.StatusCreated {
		t.Fatalf("create API token: status %d body %s", status, body)
	}
	var createdToken struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &createdToken); err != nil {
		t.Fatalf("decode API token: %v (%s)", err, body)
	}
	if createdToken.Token == "" {
		t.Fatalf("created API token response did not include one-time token material")
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "cap-nhi-02-cross-surface",
		"kind": "nhi_cross_surface",
		"config": map[string]any{
			"observations": []map[string]any{
				{"surface": "idp", "system": "okta", "external_id": "app/payments", "principal": "payments-oauth", "owner": "platform", "credential_kind": "oauth_app", "scopes": []string{"payments.read"}},
				{"surface": "cloud", "system": "aws-iam", "external_id": "role/payments-prod", "principal": "arn:aws:iam::111111111111:role/payments-prod", "owner": "platform", "credential_kind": "iam_role"},
				{"surface": "saas", "system": "github", "external_id": "hooks/42", "principal": "payments-webhook", "owner": "devex", "credential_kind": "webhook"},
				{"surface": "on_prem", "system": "ldap", "external_id": "svc-payments", "principal": "svc-payments", "owner": "identity", "credential_kind": "service_account"},
				{"surface": "code", "system": "github-code-search", "external_id": "repo/payments/path/deploy.yaml", "principal": "payments-deploy-key", "owner": "devex", "credential_kind": "ssh_key"},
				{"surface": "ci", "system": "github-actions", "external_id": "repo/payments/env/prod", "principal": "payments-ci-pat", "owner": "devex", "credential_kind": "pat"},
				{"surface": "cloud", "system": "aws-iam", "external_id": "access-key/AKIAEXAMPLE", "principal": "payments-api-key", "owner": "platform", "credential_kind": "api_key"},
				{"surface": "saas", "system": "vault", "external_id": "secret/data/payments/db", "principal": "payments-db-secret", "owner": "platform", "credential_kind": "secret"},
				{"surface": "ci", "system": "github-actions", "external_id": "oidc/payments-deploy", "principal": "payments-workload-oidc", "owner": "devex", "credential_kind": "workload_identity"},
			},
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create cross-surface inventory source: status %d body %s", status, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatalf("decode source: %v (%s)", err, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{"source_id": source.ID})
	if status != http.StatusCreated {
		t.Fatalf("start cross-surface inventory run: status %d body %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain cross-surface inventory run: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/nhi/inventory", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list unified NHI inventory: status %d body %s", status, body)
	}
	var inventory struct {
		Items []struct {
			Kind        string         `json:"kind"`
			Source      string         `json:"source"`
			DisplayName string         `json:"display_name"`
			Metadata    map[string]any `json:"metadata"`
		} `json:"items"`
		Summary  map[string]int `json:"summary"`
		Coverage []string       `json:"coverage"`
	}
	if err := json.Unmarshal(body, &inventory); err != nil {
		t.Fatalf("decode unified NHI inventory: %v (%s)", err, body)
	}
	if len(inventory.Items) < 10 {
		t.Fatalf("inventory returned %d items, want first-party plus cross-surface NHI denominator: %s", len(inventory.Items), body)
	}
	seen := map[string]bool{}
	for _, item := range inventory.Items {
		if item.Kind == "" || item.Source == "" || item.DisplayName == "" {
			t.Fatalf("inventory item lacks normalized kind/source/display name: %+v", item)
		}
		seen[item.Kind] = true
	}
	for _, want := range []string{"certificate", "service_account", "api_key", "oauth_app", "token", "secret", "iam_role", "ssh_key", "webhook", "workload_identity"} {
		if !seen[want] {
			t.Fatalf("unified NHI inventory missing %s; seen=%+v body=%s", want, seen, body)
		}
		if inventory.Summary[want] == 0 {
			t.Fatalf("summary missing count for %s: %+v", want, inventory.Summary)
		}
	}
	if !containsString(inventory.Coverage, "personal_access_token") {
		t.Fatalf("coverage denominator does not enumerate personal_access_token: %+v", inventory.Coverage)
	}
	if strings.Contains(string(body), createdToken.Token) {
		t.Fatalf("unified NHI inventory leaked one-time API token material: %s", body)
	}
}

// TestServedServiceAccountDiscoveryCAPNHI03EndToEnd proves CAP-NHI-03 is served
// through a dedicated metadata-only source kind that covers both AD/on-prem and
// cloud service-account inventory, then projects the findings through the normal
// tenant-scoped discovery event path.
func TestServedServiceAccountDiscoveryCAPNHI03EndToEnd(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "service-account-inventory",
		"kind": "service_account",
		"config": map[string]any{
			"accounts": []map[string]any{
				{
					"surface":         "active_directory",
					"provider":        "ad",
					"directory":       "corp.example",
					"account_id":      "S-1-5-21-1000",
					"principal":       "svc-payments@corp.example",
					"display_name":    "Payments service account",
					"owner":           "identity",
					"enabled":         true,
					"groups":          []string{"CN=Payments,OU=Service Accounts,DC=corp,DC=example"},
					"credential_refs": []string{"ad:corp.example:svc-payments"},
				},
				{
					"surface":         "cloud",
					"provider":        "aws-iam",
					"directory":       "111111111111",
					"account_id":      "role/payments-prod",
					"principal":       "arn:aws:iam::111111111111:role/payments-prod",
					"display_name":    "payments-prod role",
					"owner":           "platform",
					"privileged":      true,
					"roles":           []string{"AdministratorAccess"},
					"credential_refs": []string{"aws:iam:role/payments-prod"},
				},
			},
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create service-account source: status %d body %s", status, body)
	}
	var source struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatalf("decode source: %v (%s)", err, body)
	}
	if source.ID == "" || source.Kind != "service_account" {
		t.Fatalf("bad service-account source response: %+v", source)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{
		"source_id": source.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("start service-account run: status %d body %s", status, body)
	}
	var queued struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &queued); err != nil {
		t.Fatalf("decode queued run: %v (%s)", err, body)
	}
	if queued.ID == "" || queued.Status != "queued" {
		t.Fatalf("bad queued run: %+v", queued)
	}

	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain service-account discovery outbox: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get service-account run: status %d body %s", status, body)
	}
	var completed struct {
		Status     string `json:"status"`
		Targets    int    `json:"targets"`
		Discovered int    `json:"discovered"`
		Failed     int    `json:"failed"`
	}
	if err := json.Unmarshal(body, &completed); err != nil {
		t.Fatalf("decode completed run: %v (%s)", err, body)
	}
	if completed.Status != "succeeded" || completed.Targets != 2 || completed.Discovered != 2 || completed.Failed != 0 {
		t.Fatalf("completed run = %+v, want two successful service-account observations", completed)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list service-account findings: status %d body %s", status, body)
	}
	var findings struct {
		Items []struct {
			Kind        string         `json:"kind"`
			Ref         string         `json:"ref"`
			Provenance  string         `json:"provenance"`
			Fingerprint string         `json:"fingerprint"`
			RiskScore   int            `json:"risk_score"`
			Metadata    map[string]any `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &findings); err != nil {
		t.Fatalf("decode service-account findings: %v (%s)", err, body)
	}
	if len(findings.Items) != 2 {
		t.Fatalf("findings count = %d body %s, want 2", len(findings.Items), body)
	}
	surfaces := map[string]bool{}
	for _, f := range findings.Items {
		if f.Kind != "service_account" || f.Ref == "" || f.Fingerprint == "" || !strings.HasPrefix(f.Provenance, "service_account:") {
			t.Fatalf("bad service-account finding: %+v", f)
		}
		if f.RiskScore <= 0 {
			t.Fatalf("service-account finding should carry risk score: %+v", f)
		}
		if got, _ := f.Metadata["capability"].(string); got != "CAP-NHI-03" {
			t.Fatalf("capability metadata = %q, want CAP-NHI-03", got)
		}
		surface, _ := f.Metadata["surface"].(string)
		surfaces[surface] = true
	}
	for _, surface := range []string{"ad", "cloud"} {
		if !surfaces[surface] {
			t.Fatalf("surface %q was not represented in findings: %+v", surface, surfaces)
		}
	}
	if strings.Contains(string(body), "raw-value") || strings.Contains(string(body), "password") {
		t.Fatalf("service-account discovery findings leaked inline credential material: %s", body)
	}
}

// TestServedOAuthGrantDiscoveryCAPOAUTH01EndToEnd is the COMPETE-002 proof:
// CAP-OAUTH-01 is served through the tenant-scoped discovery source/run/finding
// path for metadata-only OAuth app grants, SaaS-to-SaaS consent, and scopes.
func TestServedOAuthGrantDiscoveryCAPOAUTH01EndToEnd(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "oauth-grants",
		"kind": "oauth_grant",
		"config": map[string]any{
			"grants": []map[string]any{
				{
					"provider":     "okta",
					"app_id":       "0oa-payments",
					"app_name":     "Payments BI Export",
					"principal":    "payments-bi-export",
					"resource":     "google-workspace",
					"scopes":       []string{"drive.readonly", "admin.directory.user.readonly"},
					"consent_type": "admin",
					"third_party":  true,
					"owner":        "finance-platform",
				},
				{
					"provider":     "entra-id",
					"app_id":       "app-invoice-sync",
					"app_name":     "Invoice Sync",
					"principal":    "invoice-sync",
					"resource":     "salesforce",
					"scopes":       []string{"api.read", "contacts.write"},
					"consent_type": "user",
					"third_party":  true,
					"owner":        "revops",
				},
			},
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create OAuth grant source: status %d body %s", status, body)
	}
	var source struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatalf("decode OAuth grant source: %v (%s)", err, body)
	}
	if source.ID == "" || source.Kind != "oauth_grant" {
		t.Fatalf("bad OAuth grant source response: %+v", source)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{
		"source_id": source.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("start OAuth grant run: status %d body %s", status, body)
	}
	var queued struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &queued); err != nil {
		t.Fatalf("decode queued OAuth grant run: %v (%s)", err, body)
	}
	if queued.ID == "" || queued.Status != "queued" {
		t.Fatalf("bad queued OAuth grant run: %+v", queued)
	}

	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain OAuth grant discovery outbox: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get OAuth grant run: status %d body %s", status, body)
	}
	var completed struct {
		Status     string `json:"status"`
		Targets    int    `json:"targets"`
		Discovered int    `json:"discovered"`
		Failed     int    `json:"failed"`
	}
	if err := json.Unmarshal(body, &completed); err != nil {
		t.Fatalf("decode completed OAuth grant run: %v (%s)", err, body)
	}
	if completed.Status != "succeeded" || completed.Targets != 2 || completed.Discovered != 2 || completed.Failed != 0 {
		t.Fatalf("completed OAuth grant run = %+v, want two discovered grants", completed)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list OAuth grant findings: status %d body %s", status, body)
	}
	if strings.Contains(string(body), "raw-value") || strings.Contains(string(body), "client_secret") {
		t.Fatalf("OAuth grant discovery findings leaked inline credential material: %s", body)
	}
	var findings struct {
		Items []struct {
			Kind        string         `json:"kind"`
			Ref         string         `json:"ref"`
			Provenance  string         `json:"provenance"`
			Fingerprint string         `json:"fingerprint"`
			RiskScore   int            `json:"risk_score"`
			Metadata    map[string]any `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &findings); err != nil {
		t.Fatalf("decode OAuth grant findings: %v (%s)", err, body)
	}
	if len(findings.Items) != 2 {
		t.Fatalf("OAuth grant finding count = %d body %s, want 2", len(findings.Items), body)
	}
	providers := map[string]bool{}
	for _, f := range findings.Items {
		if f.Kind != "oauth_grant" || f.Ref == "" || f.Fingerprint == "" || !strings.HasPrefix(f.Provenance, "oauth_grant:") {
			t.Fatalf("bad OAuth grant finding: %+v", f)
		}
		if f.RiskScore <= 0 {
			t.Fatalf("OAuth grant finding should carry risk score: %+v", f)
		}
		provider, _ := f.Metadata["provider"].(string)
		providers[provider] = true
		if f.Metadata["app_id"] == "" || f.Metadata["resource"] == "" {
			t.Fatalf("OAuth grant finding is missing app/resource metadata: %+v", f)
		}
		scopes, ok := f.Metadata["scopes"].([]any)
		if !ok || len(scopes) == 0 {
			t.Fatalf("OAuth grant finding is missing scope metadata: %+v", f)
		}
	}
	for _, provider := range []string{"okta", "entra-id"} {
		if !providers[provider] {
			t.Fatalf("provider %q was not represented in findings: %+v", provider, providers)
		}
	}

	for _, eventType := range []string{"discovery.source.upserted", "discovery.run.queued", "discovery.finding.recorded", "discovery.run.completed"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing %s event; OAuth grant discovery is not fully event-sourced", eventType)
		}
	}
}

// TestServedNHIBehaviorAnomalyCAPITDR01EndToEnd is the COMPETE-003 proof:
// CAP-ITDR-01 is served through tenant-scoped discovery source/run/finding
// records for NHI behavior baselines and anomaly detection across IP, geo,
// user-agent, usage-spike, and off-hours dimensions.
func TestServedNHIBehaviorAnomalyCAPITDR01EndToEnd(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "nhi-behavior",
		"kind": "nhi_behavior",
		"config": map[string]any{
			"business_hours": map[string]any{"start_hour": 8, "end_hour": 18},
			"events": []map[string]any{
				{
					"principal":   "payments-api",
					"occurred_at": "2026-06-01T10:00:00Z",
					"ip":          "198.51.100.10",
					"geo":         "US",
					"user_agent":  "payments-agent/1.0",
					"action":      "token_use",
					"usage_count": 10,
					"baseline":    true,
				},
				{
					"principal":   "payments-api",
					"occurred_at": "2026-06-02T02:15:00Z",
					"ip":          "203.0.113.9",
					"geo":         "DE",
					"user_agent":  "curl/8.7",
					"action":      "token_use",
					"usage_count": 90,
				},
			},
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create NHI behavior source: status %d body %s", status, body)
	}
	var source struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatalf("decode NHI behavior source: %v (%s)", err, body)
	}
	if source.ID == "" || source.Kind != "nhi_behavior" {
		t.Fatalf("bad NHI behavior source response: %+v", source)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{
		"source_id": source.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("start NHI behavior run: status %d body %s", status, body)
	}
	var queued struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &queued); err != nil {
		t.Fatalf("decode queued NHI behavior run: %v (%s)", err, body)
	}
	if queued.ID == "" || queued.Status != "queued" {
		t.Fatalf("bad queued NHI behavior run: %+v", queued)
	}

	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain NHI behavior outbox: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get NHI behavior run: status %d body %s", status, body)
	}
	var completed struct {
		Status     string `json:"status"`
		Targets    int    `json:"targets"`
		Discovered int    `json:"discovered"`
		Failed     int    `json:"failed"`
	}
	if err := json.Unmarshal(body, &completed); err != nil {
		t.Fatalf("decode completed NHI behavior run: %v (%s)", err, body)
	}
	if completed.Status != "succeeded" || completed.Targets != 1 || completed.Discovered != 1 || completed.Failed != 0 {
		t.Fatalf("completed NHI behavior run = %+v, want one anomaly finding", completed)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list NHI behavior findings: status %d body %s", status, body)
	}
	if strings.Contains(string(body), "raw-value") || strings.Contains(string(body), "token\":\"") {
		t.Fatalf("NHI behavior findings leaked inline credential material: %s", body)
	}
	var findings struct {
		Items []struct {
			Kind        string         `json:"kind"`
			Ref         string         `json:"ref"`
			Provenance  string         `json:"provenance"`
			Fingerprint string         `json:"fingerprint"`
			RiskScore   int            `json:"risk_score"`
			Metadata    map[string]any `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &findings); err != nil {
		t.Fatalf("decode NHI behavior findings: %v (%s)", err, body)
	}
	if len(findings.Items) != 1 {
		t.Fatalf("NHI behavior finding count = %d body %s, want 1", len(findings.Items), body)
	}
	f := findings.Items[0]
	if f.Kind != "nhi_behavior_anomaly" || f.Ref != "payments-api" || f.Fingerprint == "" || !strings.HasPrefix(f.Provenance, "nhi_behavior:payments-api:") {
		t.Fatalf("bad NHI behavior finding: %+v", f)
	}
	if f.RiskScore < 90 {
		t.Fatalf("NHI behavior finding risk score = %d, want high confidence anomaly", f.RiskScore)
	}
	reasons, ok := f.Metadata["anomaly_reasons"].([]any)
	if !ok {
		t.Fatalf("NHI behavior finding is missing anomaly reasons: %+v", f)
	}
	seen := map[string]bool{}
	for _, reason := range reasons {
		if s, ok := reason.(string); ok {
			seen[s] = true
		}
	}
	for _, reason := range []string{"unfamiliar_ip", "unfamiliar_geo", "unfamiliar_user_agent", "usage_spike", "off_hours"} {
		if !seen[reason] {
			t.Fatalf("reason %q missing from NHI behavior anomaly: %+v", reason, seen)
		}
	}

	for _, eventType := range []string{"discovery.source.upserted", "discovery.run.queued", "discovery.finding.recorded", "discovery.run.completed"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing %s event; NHI behavior discovery is not fully event-sourced", eventType)
		}
	}
}

// TestServedCompromisedCredentialDetectionCAPITDR02EndToEnd is the COMPETE-008
// proof: CAP-ITDR-02 is served through tenant-scoped discovery source/run/finding
// records for stolen-token and compromised-credential evidence, with only
// credential references and external evidence refs stored in the control plane.
func TestServedCompromisedCredentialDetectionCAPITDR02EndToEnd(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "compromised-credentials",
		"kind": "credential_compromise",
		"config": map[string]any{
			"signals": []map[string]any{
				{
					"principal":       "payments-api",
					"credential_ref":  "api-token:payments-ci",
					"credential_kind": "api_token",
					"provider":        "github-actions",
					"detector":        "honeytoken",
					"observed_at":     "2026-06-03T03:15:00Z",
					"reason":          "revoked token replayed from unfamiliar network",
					"confidence":      "critical",
					"evidence_refs": []string{
						"audit:api-token-use/evt-42",
						"threatintel:leak/sha256",
					},
					"source_event_ref": "github-audit:evt-42",
					"ip":               "203.0.113.44",
					"geo":              "DE",
					"user_agent":       "curl/8.7",
					"action":           "token_use",
					"owner":            "platform",
				},
			},
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create compromised-credential source: status %d body %s", status, body)
	}
	var source struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatalf("decode compromised-credential source: %v (%s)", err, body)
	}
	if source.ID == "" || source.Kind != "credential_compromise" {
		t.Fatalf("bad compromised-credential source response: %+v", source)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{
		"source_id": source.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("start compromised-credential run: status %d body %s", status, body)
	}
	var queued struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &queued); err != nil {
		t.Fatalf("decode queued compromised-credential run: %v (%s)", err, body)
	}
	if queued.ID == "" || queued.Status != "queued" {
		t.Fatalf("bad queued compromised-credential run: %+v", queued)
	}

	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain compromised-credential outbox: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get compromised-credential run: status %d body %s", status, body)
	}
	var completed struct {
		Status     string `json:"status"`
		Targets    int    `json:"targets"`
		Discovered int    `json:"discovered"`
		Failed     int    `json:"failed"`
	}
	if err := json.Unmarshal(body, &completed); err != nil {
		t.Fatalf("decode completed compromised-credential run: %v (%s)", err, body)
	}
	if completed.Status != "succeeded" || completed.Targets != 1 || completed.Discovered != 1 || completed.Failed != 0 {
		t.Fatalf("completed compromised-credential run = %+v, want one finding", completed)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list compromised-credential findings: status %d body %s", status, body)
	}
	if strings.Contains(string(body), "raw-token-value") || strings.Contains(string(body), "access_token") || strings.Contains(string(body), "token\":\"") {
		t.Fatalf("compromised-credential findings leaked inline credential material: %s", body)
	}
	var findings struct {
		Items []struct {
			Kind        string         `json:"kind"`
			Ref         string         `json:"ref"`
			Provenance  string         `json:"provenance"`
			Fingerprint string         `json:"fingerprint"`
			RiskScore   int            `json:"risk_score"`
			Metadata    map[string]any `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &findings); err != nil {
		t.Fatalf("decode compromised-credential findings: %v (%s)", err, body)
	}
	if len(findings.Items) != 1 {
		t.Fatalf("compromised-credential finding count = %d body %s, want 1", len(findings.Items), body)
	}
	f := findings.Items[0]
	if f.Kind != "compromised_credential" || f.Ref != "api-token:payments-ci" || f.Fingerprint == "" || !strings.HasPrefix(f.Provenance, "credential_compromise:github-actions:honeytoken:") {
		t.Fatalf("bad compromised-credential finding: %+v", f)
	}
	if f.RiskScore < 95 {
		t.Fatalf("compromised-credential finding risk score = %d, want critical stolen-token signal", f.RiskScore)
	}
	if f.Metadata["owasp_category"] != "NHI2" || f.Metadata["capability"] != "CAP-ITDR-02" {
		t.Fatalf("compromised-credential finding missing CAP-ITDR-02 metadata: %+v", f.Metadata)
	}
	refs, ok := f.Metadata["evidence_refs"].([]any)
	if !ok || len(refs) != 2 {
		t.Fatalf("compromised-credential finding is missing evidence refs: %+v", f)
	}

	for _, eventType := range []string{"discovery.source.upserted", "discovery.run.queued", "discovery.finding.recorded", "discovery.run.completed"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing %s event; compromised-credential discovery is not fully event-sourced", eventType)
		}
	}
}

// TestServedKubernetesIngressGatewayAutoIssuanceCAPK8S03EndToEnd is the
// COMPETE-004 proof: CAP-K8S-03 is served through tenant-scoped discovery
// source/run/finding records and mints signer-backed public certificate inventory
// rows for Kubernetes Ingress and Gateway API TLS resources.
func TestServedKubernetesIngressGatewayAutoIssuanceCAPK8S03EndToEnd(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "certs:read")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "k8s-ingress-gateway",
		"kind": "k8s_ingress_gateway",
		"config": map[string]any{
			"resources": []map[string]any{
				{
					"kind":            "Ingress",
					"api_version":     "networking.k8s.io/v1",
					"namespace":       "payments",
					"name":            "payments-web",
					"tls_secret_name": "payments-web-tls",
					"hosts":           []string{"payments.example.com"},
					"auto_issue":      true,
				},
				{
					"kind":            "Gateway",
					"api_version":     "gateway.networking.k8s.io/v1",
					"namespace":       "edge",
					"name":            "public",
					"tls_secret_name": "edge-public-tls",
					"hosts":           []string{"edge.example.com", "api.example.com"},
					"auto_issue":      true,
				},
			},
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create Kubernetes ingress/gateway source: status %d body %s", status, body)
	}
	var source struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatalf("decode Kubernetes source: %v (%s)", err, body)
	}
	if source.ID == "" || source.Kind != "k8s_ingress_gateway" {
		t.Fatalf("bad Kubernetes source response: %+v", source)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{
		"source_id": source.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("start Kubernetes ingress/gateway run: status %d body %s", status, body)
	}
	var queued struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &queued); err != nil {
		t.Fatalf("decode queued Kubernetes run: %v (%s)", err, body)
	}
	if queued.ID == "" || queued.Status != "queued" {
		t.Fatalf("bad queued Kubernetes run: %+v", queued)
	}

	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain Kubernetes ingress/gateway outbox: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get Kubernetes ingress/gateway run: status %d body %s", status, body)
	}
	var completed struct {
		Status     string `json:"status"`
		Targets    int    `json:"targets"`
		Discovered int    `json:"discovered"`
		Failed     int    `json:"failed"`
	}
	if err := json.Unmarshal(body, &completed); err != nil {
		t.Fatalf("decode completed Kubernetes run: %v (%s)", err, body)
	}
	if completed.Status != "succeeded" || completed.Targets != 2 || completed.Discovered != 2 || completed.Failed != 0 {
		t.Fatalf("completed Kubernetes run = %+v, want two auto-issued resources", completed)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list Kubernetes findings: status %d body %s", status, body)
	}
	if strings.Contains(string(body), "raw-value") || strings.Contains(string(body), "private_key") {
		t.Fatalf("Kubernetes ingress/gateway findings leaked credential material: %s", body)
	}
	var findings struct {
		Items []struct {
			Kind        string         `json:"kind"`
			Ref         string         `json:"ref"`
			Provenance  string         `json:"provenance"`
			Fingerprint string         `json:"fingerprint"`
			Metadata    map[string]any `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &findings); err != nil {
		t.Fatalf("decode Kubernetes findings: %v (%s)", err, body)
	}
	if len(findings.Items) != 2 {
		t.Fatalf("Kubernetes finding count = %d body %s, want 2", len(findings.Items), body)
	}
	seenResources := map[string]bool{}
	for _, f := range findings.Items {
		if f.Kind != "k8s_tls_auto_issuance" || f.Ref == "" || f.Fingerprint == "" || !strings.HasPrefix(f.Provenance, "k8s_ingress_gateway:") {
			t.Fatalf("bad Kubernetes auto-issuance finding: %+v", f)
		}
		resourceKind, _ := f.Metadata["resource_kind"].(string)
		namespace, _ := f.Metadata["namespace"].(string)
		name, _ := f.Metadata["name"].(string)
		seenResources[resourceKind+":"+namespace+"/"+name] = true
		hosts, ok := f.Metadata["hosts"].([]any)
		if !ok || len(hosts) == 0 {
			t.Fatalf("Kubernetes finding is missing host metadata: %+v", f)
		}
		if f.Metadata["tls_secret_name"] == "" {
			t.Fatalf("Kubernetes finding is missing TLS Secret metadata: %+v", f)
		}
	}
	for _, resource := range []string{"Ingress:payments/payments-web", "Gateway:edge/public"} {
		if !seenResources[resource] {
			t.Fatalf("resource %q was not represented in findings: %+v", resource, seenResources)
		}
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/certificates", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list certificates after Kubernetes auto-issuance: status %d body %s", status, body)
	}
	var certs struct {
		Items []struct {
			DeploymentLocation string   `json:"deployment_location"`
			Source             string   `json:"source"`
			Fingerprint        string   `json:"fingerprint"`
			SANs               []string `json:"sans"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &certs); err != nil {
		t.Fatalf("decode Kubernetes certificates: %v (%s)", err, body)
	}
	if len(certs.Items) != 2 {
		t.Fatalf("Kubernetes auto-issuance certificate count = %d body %s, want 2", len(certs.Items), body)
	}
	seenLocations := map[string]bool{}
	for _, cert := range certs.Items {
		if cert.Source != "discovery:k8s_ingress_gateway" || cert.Fingerprint == "" {
			t.Fatalf("bad Kubernetes auto-issued cert: %+v", cert)
		}
		seenLocations[cert.DeploymentLocation] = true
		if len(cert.SANs) == 0 {
			t.Fatalf("Kubernetes auto-issued cert missing SANs: %+v", cert)
		}
	}
	for _, location := range []string{"k8s:Ingress:payments/payments-web:secret/payments-web-tls", "k8s:Gateway:edge/public:secret/edge-public-tls"} {
		if !seenLocations[location] {
			t.Fatalf("certificate location %q was not represented: %+v", location, seenLocations)
		}
	}

	for _, eventType := range []string{"discovery.source.upserted", "discovery.run.queued", "discovery.finding.recorded", "certificate.recorded", "discovery.run.completed"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing %s event; Kubernetes auto-issuance is not fully event-sourced", eventType)
		}
	}
}

// TestServedCloudCertificateDiscoveryACMEndToEnd is the DISC-04 acceptance proof:
// the served discovery dispatcher constructs the AWS ACM cloud-cert collector from a
// credential-reference-only source config, runs it from the outbox worker, records
// metadata-only discovery findings, and feeds the certificate inventory. The ACM
// backend here is an ACM-compatible HTTP double with read-only List/Get operations;
// real cloud credentials can point the same config at AWS ACM.
func TestServedCloudCertificateDiscoveryACMEndToEnd(t *testing.T) {
	arn := "arn:aws:acm:us-east-1:111111111111:certificate/cloud-edge"
	var seen []string
	acm := servedACMDouble(map[string]string{
		arn: servedCloudCertPEM(t, "cloud-edge.example", "cloud-edge.example"),
	}, &seen)
	t.Cleanup(acm.Close)
	t.Setenv("TRSTCTL_DISCOVERY_AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("TRSTCTL_DISCOVERY_AWS_SECRET_ACCESS_KEY", "SECRET")

	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "certs:read")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "aws-acm-east",
		"kind": "cloud_certificate",
		"config": map[string]any{
			"providers": []map[string]any{
				{
					"provider":               "aws-acm",
					"region":                 "us-east-1",
					"endpoint":               acm.URL,
					"allow_private_endpoint": true,
					"access_key_id_ref":      "env:TRSTCTL_DISCOVERY_AWS_ACCESS_KEY_ID",
					"secret_access_key_ref":  "env:TRSTCTL_DISCOVERY_AWS_SECRET_ACCESS_KEY",
				},
			},
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create cloud discovery source: status %d body %s", status, body)
	}
	var source struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatalf("decode source: %v (%s)", err, body)
	}
	if source.ID == "" || source.Kind != "cloud_certificate" {
		t.Fatalf("bad cloud source response: %+v", source)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{
		"source_id": source.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("start cloud discovery run: status %d body %s", status, body)
	}
	var queued struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &queued); err != nil {
		t.Fatalf("decode queued run: %v (%s)", err, body)
	}
	if queued.ID == "" || queued.Status != "queued" {
		t.Fatalf("bad queued run: %+v", queued)
	}

	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain cloud discovery outbox: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get cloud discovery run: status %d body %s", status, body)
	}
	var completed struct {
		Status     string `json:"status"`
		Targets    int    `json:"targets"`
		Discovered int    `json:"discovered"`
		Failed     int    `json:"failed"`
	}
	if err := json.Unmarshal(body, &completed); err != nil {
		t.Fatalf("decode completed cloud run: %v (%s)", err, body)
	}
	if completed.Status != "succeeded" || completed.Targets != 1 || completed.Discovered != 1 || completed.Failed != 0 {
		t.Fatalf("completed cloud run = %+v, want one successful cloud discovery", completed)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list cloud findings: status %d body %s", status, body)
	}
	if strings.Contains(string(body), "SECRET") || strings.Contains(string(body), "AKID") {
		t.Fatalf("served cloud finding leaked credential material or identifiers: %s", body)
	}
	var findings struct {
		Items []struct {
			Kind        string          `json:"kind"`
			Ref         string          `json:"ref"`
			Provenance  string          `json:"provenance"`
			Fingerprint string          `json:"fingerprint"`
			Metadata    json.RawMessage `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &findings); err != nil {
		t.Fatalf("decode cloud findings: %v (%s)", err, body)
	}
	if len(findings.Items) != 1 {
		t.Fatalf("cloud findings count = %d body %s, want 1", len(findings.Items), body)
	}
	f := findings.Items[0]
	if f.Kind != "x509_certificate" || f.Ref != arn || f.Provenance != "cloud:aws-acm:"+arn || f.Fingerprint == "" {
		t.Fatalf("bad cloud finding: %+v", f)
	}
	var meta map[string]any
	if err := json.Unmarshal(f.Metadata, &meta); err != nil {
		t.Fatalf("decode cloud metadata: %v (%s)", err, f.Metadata)
	}
	if meta["provider"] != "aws-acm" || meta["location"] != "us-east-1" || meta["resource_id"] != arn {
		t.Fatalf("cloud finding metadata = %+v, want provider/location/resource id", meta)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/certificates", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list certificates after cloud discovery: status %d body %s", status, body)
	}
	var certs struct {
		Items []struct {
			DeploymentLocation string `json:"deployment_location"`
			Source             string `json:"source"`
			Fingerprint        string `json:"fingerprint"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &certs); err != nil {
		t.Fatalf("decode certificates: %v (%s)", err, body)
	}
	if len(certs.Items) != 1 || certs.Items[0].DeploymentLocation != arn || certs.Items[0].Source != "discovery:cloud:aws-acm" || certs.Items[0].Fingerprint == "" {
		t.Fatalf("inventory was not populated from cloud discovery: %+v", certs.Items)
	}

	for _, target := range seen {
		if target != "CertificateManager.ListCertificates" && target != "CertificateManager.GetCertificate" {
			t.Fatalf("cloud discovery invoked non-read-only ACM operation %q; seen=%v", target, seen)
		}
	}
	if len(seen) == 0 {
		t.Fatal("cloud discovery did not call the ACM backend")
	}
	for _, eventType := range []string{"discovery.source.upserted", "discovery.run.queued", "discovery.finding.recorded", "certificate.recorded"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing %s event; cloud discovery is not event-sourced", eventType)
		}
	}
}

// TestServedCloudSecretDiscoveryAWSSecretsManagerEndToEnd is the C7-2 acceptance
// proof: a cloud_secret source uses credential references only, runs through the
// discovery outbox worker, reads AWS Secrets Manager through List/Get only, records
// metadata-only findings, and lands in the C7-1 triage lifecycle as unmanaged.
func TestServedCloudSecretDiscoveryAWSSecretsManagerEndToEnd(t *testing.T) {
	certSecret := "tls/web"
	plainSecret := "app/db"
	var seen []string
	sm := servedAWSSecretsManagerDouble(map[string]string{
		certSecret:  servedCloudCertPEM(t, "sm-web.example", "sm-web.example"),
		plainSecret: "not a certificate",
	}, map[string]map[string]string{
		certSecret:  {"type": "certificate"},
		plainSecret: {"type": "certificate"},
	}, &seen)
	t.Cleanup(sm.Close)
	t.Setenv("TRSTCTL_DISCOVERY_AWS_SM_ACCESS_KEY_ID", "AKID")
	t.Setenv("TRSTCTL_DISCOVERY_AWS_SM_SECRET_ACCESS_KEY", "SECRET")

	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name": "aws-sm-east",
		"kind": "cloud_secret",
		"config": map[string]any{
			"providers": []map[string]any{
				{
					"provider":               "aws-secrets-manager",
					"region":                 "us-east-1",
					"endpoint":               sm.URL,
					"allow_private_endpoint": true,
					"access_key_id_ref":      "env:TRSTCTL_DISCOVERY_AWS_SM_ACCESS_KEY_ID",
					"secret_access_key_ref":  "env:TRSTCTL_DISCOVERY_AWS_SM_SECRET_ACCESS_KEY",
					"tag_key":                "type",
					"tag_value":              "certificate",
				},
			},
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create cloud-secret source: status %d body %s", status, body)
	}
	var source struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatalf("decode source: %v (%s)", err, body)
	}
	if source.ID == "" || source.Kind != "cloud_secret" {
		t.Fatalf("bad cloud-secret source response: %+v", source)
	}

	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{
		"source_id": source.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("start cloud-secret discovery run: status %d body %s", status, body)
	}
	var queued struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &queued); err != nil {
		t.Fatalf("decode queued run: %v (%s)", err, body)
	}
	if queued.ID == "" || queued.Status != "queued" {
		t.Fatalf("bad queued run: %+v", queued)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain cloud-secret outbox: %v", err)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get cloud-secret discovery run: status %d body %s", status, body)
	}
	var completed struct {
		Status     string `json:"status"`
		Targets    int    `json:"targets"`
		Discovered int    `json:"discovered"`
		Failed     int    `json:"failed"`
	}
	if err := json.Unmarshal(body, &completed); err != nil {
		t.Fatalf("decode completed cloud-secret run: %v (%s)", err, body)
	}
	if completed.Status != "succeeded" || completed.Targets != 1 || completed.Discovered != 1 || completed.Failed != 0 {
		t.Fatalf("completed cloud-secret run = %+v, want one successful import finding", completed)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list cloud-secret findings: status %d body %s", status, body)
	}
	if strings.Contains(string(body), "SECRET") || strings.Contains(string(body), "not a certificate") {
		t.Fatalf("served cloud-secret finding leaked secret material: %s", body)
	}
	var findings struct {
		Items []struct {
			Kind         string          `json:"kind"`
			Ref          string          `json:"ref"`
			Provenance   string          `json:"provenance"`
			Fingerprint  string          `json:"fingerprint"`
			TriageStatus string          `json:"triage_status"`
			Metadata     json.RawMessage `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &findings); err != nil {
		t.Fatalf("decode cloud-secret findings: %v (%s)", err, body)
	}
	if len(findings.Items) != 1 {
		t.Fatalf("cloud-secret findings count = %d body %s, want 1", len(findings.Items), body)
	}
	f := findings.Items[0]
	wantRef := "arn:aws:secretsmanager:us-east-1:111111111111:secret:" + certSecret
	if f.Kind != "x509_certificate" || f.Ref != wantRef || f.Provenance != "aws-sm://us-east-1/"+certSecret || f.Fingerprint == "" || f.TriageStatus != "unmanaged" {
		t.Fatalf("bad cloud-secret finding: %+v", f)
	}
	var meta map[string]any
	if err := json.Unmarshal(f.Metadata, &meta); err != nil {
		t.Fatalf("decode cloud-secret metadata: %v (%s)", err, f.Metadata)
	}
	if meta["provider"] != "aws-secrets-manager" || meta["secret_name"] != certSecret || meta["resource_id"] != wantRef {
		t.Fatalf("cloud-secret metadata = %+v, want provider/secret/resource", meta)
	}
	for _, target := range seen {
		if target != "secretsmanager.ListSecrets" && target != "secretsmanager.GetSecretValue" {
			t.Fatalf("cloud-secret discovery invoked non-read-only operation %q; seen=%v", target, seen)
		}
	}
	for _, eventType := range []string{"discovery.source.upserted", "discovery.run.queued", "discovery.finding.recorded"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing %s event; cloud-secret discovery is not event-sourced", eventType)
		}
	}
}

func servedACMDouble(arnToPEM map[string]string, seen *[]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.Header.Get("X-Amz-Target")
		*seen = append(*seen, target)
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unsigned", http.StatusForbidden)
			return
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch target {
		case "CertificateManager.ListCertificates":
			var summaries []map[string]string
			for arn := range arnToPEM {
				summaries = append(summaries, map[string]string{"CertificateArn": arn})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"CertificateSummaryList": summaries})
		case "CertificateManager.GetCertificate":
			var req struct{ CertificateArn string }
			_ = json.Unmarshal(body, &req)
			_ = json.NewEncoder(w).Encode(map[string]any{"Certificate": arnToPEM[req.CertificateArn]})
		default:
			http.Error(w, "unexpected target "+target, http.StatusBadRequest)
		}
	}))
}

func servedAWSSecretsManagerDouble(secrets map[string]string, tags map[string]map[string]string, seen *[]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.Header.Get("X-Amz-Target")
		*seen = append(*seen, target)
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unsigned", http.StatusForbidden)
			return
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch target {
		case "secretsmanager.ListSecrets":
			var list []map[string]any
			for name := range secrets {
				var tagList []map[string]string
				for k, v := range tags[name] {
					tagList = append(tagList, map[string]string{"Key": k, "Value": v})
				}
				list = append(list, map[string]any{
					"Name": name,
					"ARN":  "arn:aws:secretsmanager:us-east-1:111111111111:secret:" + name,
					"Tags": tagList,
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"SecretList": list})
		case "secretsmanager.GetSecretValue":
			var req struct {
				SecretID string `json:"SecretId"`
			}
			_ = json.Unmarshal(body, &req)
			_ = json.NewEncoder(w).Encode(map[string]any{"SecretString": secrets[req.SecretID]})
		default:
			http.Error(w, "unexpected target "+target, http.StatusBadRequest)
		}
	}))
}

func servedCloudCertPEM(t *testing.T, commonName string, dns ...string) string {
	t.Helper()
	hosts := append([]string{commonName}, dns...)
	cert, err := mtls.SelfSignedServerCert(hosts, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return string(cert.TrustPEM)
}

func servedHealthLeafPEM(t *testing.T, h *servedHarness, cn string, ttl time.Duration) string {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate health leaf key: %v", err)
	}
	t.Cleanup(key.Destroy)
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: cn,
		DNSNames:   []string{cn},
	}, key)
	if err != nil {
		t.Fatalf("create health leaf CSR: %v", err)
	}
	certPEM, err := h.srv.IssueLeaf(t.Context(), csrDER, ttl)
	if err != nil {
		t.Fatalf("issue health leaf: %v", err)
	}
	return string(certPEM)
}

func ingestServedHealthCertificate(t *testing.T, h *servedHarness, tok, idemKey, certPEM, source, location string) {
	t.Helper()
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates", tok, idemKey, map[string]any{
		"pem":                 certPEM,
		"source":              source,
		"deployment_location": location,
	})
	if status != http.StatusCreated {
		t.Fatalf("ingest health certificate %q: status %d body %s", source, status, body)
	}
}
