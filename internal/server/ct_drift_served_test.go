package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/drift"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/notify/webhook"
	"trstctl.com/trstctl/internal/store"
)

func TestServedCTMonitoringAndDriftWorkers(t *testing.T) {
	secret := []byte("served-ct-drift-webhook-test-secret")
	sink := newServedWebhookSink(t, secret)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.NotificationChannels = []notify.Notifier{
			webhook.New(sink.URL(), secret, webhook.WithHTTPClient(sink.Client())),
		}
	})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", string(authz.PrivateEgress))

	shadowDER, shadowTBS, err := ctlogtest.IssueCert("shadow", "shadow.example.com")
	if err != nil {
		t.Fatal(err)
	}
	logSrv := ctlogtest.NewServer(ctlogtest.PrecertEntry(shadowDER, shadowTBS))
	t.Cleanup(logSrv.Close)

	ctRunID := createAndRunDiscoverySource(t, h, tok, "ct-log-fixture", "ct_log", map[string]any{
		"logs":                   []string{logSrv.URL()},
		"watched_domains":        []string{"example.com"},
		"allow_private_endpoint": true,
		"private_egress_cidrs":   []string{serviceNowSinkCIDR(t, logSrv.URL())},
	})
	ctFindings := discoveryFindingsForRun(t, h, tok, ctRunID)
	if len(ctFindings.Items) != 1 {
		t.Fatalf("CT findings count = %d (%s), want 1", len(ctFindings.Items), ctFindings.Raw)
	}
	if f := ctFindings.Items[0]; f.Kind != "ct_unexpected_issuance" || f.Fingerprint == "" || !strings.Contains(f.Provenance, "ct:") {
		t.Fatalf("bad CT finding: %+v", f)
	}
	alert := sink.LastAlert()
	if sink.Accepted() != 1 || alert.Kind != notify.KindUnexpectedIssuance || alert.Subject != "CN=shadow" {
		t.Fatalf("CT alert not dispatched through notification webhook: accepted=%d alert=%+v", sink.Accepted(), alert)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "leaf.pem")
	declared := []byte("declared certificate bytes")
	if err := os.WriteFile(path, []byte("drifted certificate bytes"), 0o600); err != nil {
		t.Fatalf("write drift fixture: %v", err)
	}
	driftRunID := createAndRunDiscoverySource(t, h, tok, "drift-fixture", "drift", map[string]any{
		"watched": []map[string]any{{
			"path":        path,
			"class":       "certificate",
			"fingerprint": drift.Fingerprint(declared),
			"mode":        "0600",
		}},
	})
	driftFindings := discoveryFindingsForRun(t, h, tok, driftRunID)
	if len(driftFindings.Items) != 1 {
		t.Fatalf("drift findings count = %d (%s), want 1", len(driftFindings.Items), driftFindings.Raw)
	}
	if f := driftFindings.Items[0]; f.Kind != "credential_drift" || f.Ref != path || !strings.Contains(f.Provenance, "drift:") {
		t.Fatalf("bad drift finding: %+v", f)
	}
	var meta struct {
		Type  string `json:"type"`
		Class string `json:"class"`
	}
	if err := json.Unmarshal(driftFindings.Items[0].Metadata, &meta); err != nil {
		t.Fatalf("decode drift metadata: %v (%s)", err, driftFindings.Items[0].Metadata)
	}
	if meta.Type != string(drift.Replaced) || meta.Class != "certificate" {
		t.Fatalf("drift metadata = %+v, want replaced certificate", meta)
	}

	for _, eventType := range []string{"discovery.finding.recorded", "discovery.run.completed"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("missing %s event", eventType)
		}
	}
}

func TestServedCTMonitoringDashboardConfiguresWatchlistAndFindings(t *testing.T) {
	secret := []byte("served-ct-monitoring-dashboard-secret")
	sink := newServedWebhookSink(t, secret)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.NotificationChannels = []notify.Notifier{
			webhook.New(sink.URL(), secret, webhook.WithHTTPClient(sink.Client())),
		}
	})
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", string(authz.PrivateEgress))

	shadowDER, shadowTBS, err := ctlogtest.IssueCert("shadow", "shadow.example.com")
	if err != nil {
		t.Fatal(err)
	}
	logSrv := ctlogtest.NewServer(ctlogtest.PrecertEntry(shadowDER, shadowTBS))
	t.Cleanup(logSrv.Close)

	status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/discovery/ct-monitoring", tok, "trace-004-ct-monitoring", map[string]any{
		"name":                   "public-ct-watch",
		"logs":                   []string{logSrv.URL()},
		"watched_domains":        []string{"example.com"},
		"max_batch":              25,
		"run_now":                true,
		"allow_private_endpoint": true,
		"private_egress_cidrs":   []string{serviceNowSinkCIDR(t, logSrv.URL())},
	})
	if status != http.StatusOK {
		t.Fatalf("configure CT monitoring: status %d body %s", status, body)
	}
	var configured struct {
		Capability string `json:"capability"`
		Source     struct {
			ID     string `json:"id"`
			Kind   string `json:"kind"`
			Name   string `json:"name"`
			Config struct {
				Logs           []string `json:"logs"`
				WatchedDomains []string `json:"watched_domains"`
				MaxBatch       int      `json:"max_batch"`
			} `json:"config"`
		} `json:"source"`
		Run struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"run"`
	}
	if err := json.Unmarshal(body, &configured); err != nil {
		t.Fatalf("decode configured CT monitoring: %v (%s)", err, body)
	}
	if configured.Capability != "F17" || configured.Source.ID == "" || configured.Source.Kind != "ct_log" || configured.Source.Name != "public-ct-watch" || configured.Run.Status != "queued" {
		t.Fatalf("bad configured CT monitoring response: %+v", configured)
	}
	if len(configured.Source.Config.Logs) != 1 || configured.Source.Config.Logs[0] != logSrv.URL() || len(configured.Source.Config.WatchedDomains) != 1 || configured.Source.Config.WatchedDomains[0] != "example.com" || configured.Source.Config.MaxBatch != 25 {
		t.Fatalf("CT source config not round-tripped: %+v", configured.Source.Config)
	}

	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain CT monitoring run: %v", err)
	}
	ctFindings := discoveryFindingsForRun(t, h, tok, configured.Run.ID)
	if len(ctFindings.Items) != 1 || ctFindings.Items[0].Kind != "ct_unexpected_issuance" {
		t.Fatalf("CT findings = %+v raw=%s, want one unexpected issuance", ctFindings.Items, ctFindings.Raw)
	}
	if sink.Accepted() != 1 || sink.LastAlert().Kind != notify.KindUnexpectedIssuance {
		t.Fatalf("CT alert not delivered through outbox-backed notification: accepted=%d alert=%+v", sink.Accepted(), sink.LastAlert())
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/ct-monitoring", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get CT monitoring: status %d body %s", status, body)
	}
	var dashboard struct {
		Capability     string   `json:"capability"`
		WatchedDomains []string `json:"watched_domains"`
		Logs           []struct {
			URL       string `json:"url"`
			NextIndex int64  `json:"next_index"`
		} `json:"logs"`
		OutboxBackedAlerts bool `json:"outbox_backed_alerts"`
		Summary            struct {
			SourceCount         int `json:"source_count"`
			WatchedDomainCount  int `json:"watched_domain_count"`
			LogCount            int `json:"log_count"`
			FindingCount        int `json:"finding_count"`
			UnexpectedIssuance  int `json:"unexpected_issuance_count"`
			OpenFindingCount    int `json:"open_finding_count"`
			OutboxAlertChannels int `json:"outbox_alert_channel_count"`
		} `json:"summary"`
		Findings []struct {
			Kind string `json:"kind"`
			Ref  string `json:"ref"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(body, &dashboard); err != nil {
		t.Fatalf("decode CT monitoring dashboard: %v (%s)", err, body)
	}
	if dashboard.Capability != "F17" || !dashboard.OutboxBackedAlerts || !containsString(dashboard.WatchedDomains, "example.com") || len(dashboard.Logs) != 1 || dashboard.Logs[0].URL != logSrv.URL() || dashboard.Logs[0].NextIndex < 1 {
		t.Fatalf("bad CT monitoring dashboard state: %+v", dashboard)
	}
	if dashboard.Summary.SourceCount != 1 || dashboard.Summary.WatchedDomainCount != 1 || dashboard.Summary.LogCount != 1 || dashboard.Summary.FindingCount != 1 || dashboard.Summary.UnexpectedIssuance != 1 || dashboard.Summary.OpenFindingCount != 1 || dashboard.Summary.OutboxAlertChannels != 1 {
		t.Fatalf("bad CT monitoring dashboard summary: %+v", dashboard.Summary)
	}
	if len(dashboard.Findings) != 1 || dashboard.Findings[0].Kind != "ct_unexpected_issuance" || !strings.Contains(dashboard.Findings[0].Ref, "shadow.example.com") {
		t.Fatalf("bad CT dashboard findings: %+v", dashboard.Findings)
	}
}

// CAP-REV-05 acceptance: rogue and non-compliant certificate detection is served
// as a tenant-scoped posture, not only as CT plumbing. The proof runs the real
// CT discovery worker, records a ct_unexpected_issuance finding and notification
// outbox alert, seeds one weak/long-lived external cert, then verifies the API
// enumerates both as actionable certificate findings without exposing DER/key
// material.
func TestServedRogueCertificateDetectionCAPREV05EndToEnd(t *testing.T) {
	secret := []byte("served-rogue-cert-webhook-test-secret")
	sink := newServedWebhookSink(t, secret)
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.NotificationChannels = []notify.Notifier{
			webhook.New(sink.URL(), secret, webhook.WithHTTPClient(sink.Client())),
		}
	})
	tok := seedScopedToken(t, h.store, h.tenant, "certs:read", "discovery:read", "discovery:write", string(authz.PrivateEgress))

	now := time.Now().UTC()
	notBefore := now.Add(-24 * time.Hour)
	notAfter := now.Add(900 * 24 * time.Hour)
	if _, err := h.store.UpsertCertificate(t.Context(), store.Certificate{
		TenantID:           h.tenant,
		Subject:            "CN=legacy.external.example.com",
		SANs:               []string{"legacy.external.example.com"},
		Issuer:             "CN=External Legacy CA",
		Serial:             "1001",
		Fingerprint:        "legacy-weak-fp",
		KeyAlgorithm:       "RSA-1024",
		NotBefore:          &notBefore,
		NotAfter:           &notAfter,
		DeploymentLocation: "f5:/Common/legacy",
		Source:             "import",
	}); err != nil {
		t.Fatalf("seed weak external certificate: %v", err)
	}

	shadowDER, shadowTBS, err := ctlogtest.IssueCert("shadow", "shadow.example.com")
	if err != nil {
		t.Fatal(err)
	}
	logSrv := ctlogtest.NewServer(ctlogtest.PrecertEntry(shadowDER, shadowTBS))
	t.Cleanup(logSrv.Close)

	ctRunID := createAndRunDiscoverySource(t, h, tok, "cap-rev-05-ct", "ct_log", map[string]any{
		"logs":                   []string{logSrv.URL()},
		"watched_domains":        []string{"example.com"},
		"allow_private_endpoint": true,
		"private_egress_cidrs":   []string{serviceNowSinkCIDR(t, logSrv.URL())},
	})
	ctFindings := discoveryFindingsForRun(t, h, tok, ctRunID)
	if len(ctFindings.Items) != 1 || ctFindings.Items[0].Kind != "ct_unexpected_issuance" {
		t.Fatalf("CT findings = %+v raw=%s, want one unexpected issuance", ctFindings.Items, ctFindings.Raw)
	}
	if sink.Accepted() != 1 || sink.LastAlert().Kind != notify.KindUnexpectedIssuance {
		t.Fatalf("CT notification outbox delivery not observed: accepted=%d alert=%+v", sink.Accepted(), sink.LastAlert())
	}

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/revocation/rogue-certificates", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list rogue certificates = %d, want 200; body=%s", status, body)
	}
	var posture struct {
		Capability string `json:"capability"`
		Summary    struct {
			TotalAnalyzed      int `json:"total_analyzed"`
			Findings           int `json:"findings"`
			Rogue              int `json:"rogue"`
			NonCompliant       int `json:"non_compliant"`
			CTUnexpected       int `json:"ct_unexpected"`
			WeakKey            int `json:"weak_key"`
			LifetimeViolations int `json:"lifetime_violations"`
			OwnerMissing       int `json:"owner_missing"`
			Critical           int `json:"critical"`
			High               int `json:"high"`
		} `json:"summary"`
		Findings []struct {
			Kind           string   `json:"kind"`
			PolicyStatus   string   `json:"policy_status"`
			Subject        string   `json:"subject"`
			Source         string   `json:"source"`
			FindingTypes   []string `json:"finding_types"`
			Severity       string   `json:"severity"`
			RiskScore      int      `json:"risk_score"`
			Recommendation string   `json:"recommendation"`
			EvidenceRefs   []string `json:"evidence_refs"`
			LogURL         string   `json:"log_url"`
		} `json:"findings"`
		EvidenceRefs []string `json:"evidence_refs"`
	}
	if err := json.Unmarshal(body, &posture); err != nil {
		t.Fatalf("decode CAP-REV-05 posture: %v body=%s", err, body)
	}
	if posture.Capability != "CAP-REV-05" || posture.Summary.TotalAnalyzed < 2 || posture.Summary.Findings != 2 {
		t.Fatalf("bad CAP-REV-05 summary %+v capability=%s", posture.Summary, posture.Capability)
	}
	if posture.Summary.Rogue != 1 || posture.Summary.NonCompliant != 1 || posture.Summary.CTUnexpected != 1 || posture.Summary.WeakKey != 1 || posture.Summary.LifetimeViolations != 1 || posture.Summary.OwnerMissing != 1 {
		t.Fatalf("wrong CAP-REV-05 classification counts: %+v", posture.Summary)
	}
	byKind := map[string]struct {
		PolicyStatus   string
		Subject        string
		Source         string
		FindingTypes   []string
		Severity       string
		RiskScore      int
		Recommendation string
		EvidenceRefs   []string
		LogURL         string
	}{}
	for _, finding := range posture.Findings {
		byKind[finding.Kind] = struct {
			PolicyStatus   string
			Subject        string
			Source         string
			FindingTypes   []string
			Severity       string
			RiskScore      int
			Recommendation string
			EvidenceRefs   []string
			LogURL         string
		}{
			PolicyStatus: finding.PolicyStatus, Subject: finding.Subject, Source: finding.Source, FindingTypes: finding.FindingTypes,
			Severity: finding.Severity, RiskScore: finding.RiskScore, Recommendation: finding.Recommendation, EvidenceRefs: finding.EvidenceRefs, LogURL: finding.LogURL,
		}
		if strings.Contains(string(body), "BEGIN") || strings.Contains(string(body), "PRIVATE KEY") {
			t.Fatalf("CAP-REV-05 response leaked PEM/key material: %s", body)
		}
	}
	rogue, ok := byKind["rogue_certificate"]
	if !ok || rogue.PolicyStatus != "rogue" || rogue.Source != "ct_log" || rogue.LogURL == "" || !containsString(rogue.FindingTypes, "ct_unexpected_issuance") || rogue.Severity != "critical" || len(rogue.EvidenceRefs) < 2 {
		t.Fatalf("bad rogue certificate finding: %+v", rogue)
	}
	nonCompliant, ok := byKind["non_compliant_certificate"]
	if !ok || nonCompliant.PolicyStatus != "non_compliant" || nonCompliant.Subject != "CN=legacy.external.example.com" || !containsString(nonCompliant.FindingTypes, "weak_key_algorithm") || !containsString(nonCompliant.FindingTypes, "lifetime_exceeds_policy") || !containsString(nonCompliant.FindingTypes, "owner_missing") || nonCompliant.RiskScore < 80 {
		t.Fatalf("bad non-compliant certificate finding: %+v", nonCompliant)
	}
	if !h.hasEvent(t, "discovery.finding.recorded") || !h.hasEvent(t, "discovery.run.completed") {
		t.Fatal("missing discovery event evidence for CAP-REV-05")
	}
}

func createAndRunDiscoverySource(t *testing.T, h *servedHarness, tok, name, kind string, cfg map[string]any) string {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, map[string]any{
		"name":   name,
		"kind":   kind,
		"config": cfg,
	})
	if status != http.StatusCreated {
		t.Fatalf("create %s discovery source: status %d body %s", kind, status, body)
	}
	var source struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatalf("decode source: %v (%s)", err, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, map[string]any{
		"source_id": source.ID,
	})
	if status != http.StatusCreated {
		t.Fatalf("start %s discovery run: status %d body %s", kind, status, body)
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
		t.Fatalf("drain %s discovery outbox: %v", kind, err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("get %s discovery run: status %d body %s", kind, status, body)
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
		t.Fatalf("%s discovery run = %+v, want one successful finding", kind, completed)
	}
	return queued.ID
}

type servedDiscoveryFindingList struct {
	Raw   []byte
	Items []struct {
		Kind        string          `json:"kind"`
		Ref         string          `json:"ref"`
		Provenance  string          `json:"provenance"`
		Fingerprint string          `json:"fingerprint"`
		Metadata    json.RawMessage `json:"metadata"`
	} `json:"items"`
}

func discoveryFindingsForRun(t *testing.T, h *servedHarness, tok, runID string) servedDiscoveryFindingList {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+runID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list discovery findings: status %d body %s", status, body)
	}
	var out servedDiscoveryFindingList
	out.Raw = body
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode discovery findings: %v (%s)", err, body)
	}
	return out
}
