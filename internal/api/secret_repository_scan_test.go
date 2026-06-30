package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
)

func TestServedRepoSecretScanningCAPSCAN01(t *testing.T) {
	handler := api.New(nil, nil, nil, api.WithInsecureHeaderResolver())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/scans/repositories", nil)
	req.Header.Set("X-Tenant-ID", "11111111-1111-1111-1111-111111111111")
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("repository scanning status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got struct {
		Capability         string `json:"capability"`
		Served             bool   `json:"served"`
		Scanner            string `json:"scanner"`
		MinimumRulesActive int    `json:"minimum_rules_active"`
		Providers          []struct {
			ID               string   `json:"id"`
			RealtimeTriggers []string `json:"realtime_triggers"`
			IngestMode       string   `json:"ingest_mode"`
			OutboxMode       string   `json:"outbox_mode"`
		} `json:"providers"`
		WebhookPaths []string `json:"webhook_paths"`
		EventFlow    []string `json:"event_flow"`
		ReleaseGates []struct {
			ID       string `json:"id"`
			Required bool   `json:"required"`
		} `json:"release_gates"`
		OperatorActions      []string `json:"operator_actions"`
		Residuals            []string `json:"residuals"`
		ArchitectureControls []string `json:"architecture_controls"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode repository scanning posture: %v", err)
	}
	if got.Capability != "CAP-SCAN-01" || !got.Served {
		t.Fatalf("capability/served = %q/%v, want CAP-SCAN-01/true", got.Capability, got.Served)
	}
	if got.MinimumRulesActive < 140 || got.Scanner == "" {
		t.Fatalf("scanner posture = %q/%d, want pinned scanner with 140+ rule floor", got.Scanner, got.MinimumRulesActive)
	}
	for _, want := range []string{"github", "gitlab", "bitbucket"} {
		if !providerListed(got.Providers, want) {
			t.Fatalf("providers missing %q: %+v", want, got.Providers)
		}
		if !containsString(got.WebhookPaths, "/api/v1/secrets/scans/repositories/"+want+"/webhook") {
			t.Fatalf("webhook paths missing %q: %+v", want, got.WebhookPaths)
		}
	}
	for _, want := range []string{"discovery.source.upserted", "discovery.run.queued", "discovery.finding.recorded", "discovery.run.completed"} {
		if !containsString(got.EventFlow, want) {
			t.Fatalf("event flow missing %q: %+v", want, got.EventFlow)
		}
	}
	for _, want := range []string{"provider-webhook-contract", "redaction-regression", "architecture-lint"} {
		if !gateRequired(got.ReleaseGates, want) {
			t.Fatalf("release gates missing required %q: %+v", want, got.ReleaseGates)
		}
	}
	for _, want := range []string{"AN-2", "AN-5", "AN-6", "AN-8"} {
		if !containsString(got.ArchitectureControls, want) {
			t.Fatalf("architecture controls missing %q: %+v", want, got.ArchitectureControls)
		}
	}
	if len(got.OperatorActions) == 0 || len(got.Residuals) == 0 {
		t.Fatalf("posture must expose operator actions and residual shortfalls: %+v", got)
	}
}

func TestServedThirdPartySecretScanningCAPSCAN04(t *testing.T) {
	handler := api.New(nil, nil, nil, api.WithInsecureHeaderResolver())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/scans/third-party", nil)
	req.Header.Set("X-Tenant-ID", "11111111-1111-1111-1111-111111111111")
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("third-party scanning status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got struct {
		Capability         string `json:"capability"`
		Served             bool   `json:"served"`
		Scanner            string `json:"scanner"`
		MinimumRulesActive int    `json:"minimum_rules_active"`
		Providers          []struct {
			ID            string   `json:"id"`
			ArtifactKinds []string `json:"artifact_kinds"`
			IngestMode    string   `json:"ingest_mode"`
			OutboxMode    string   `json:"outbox_mode"`
		} `json:"providers"`
		IngestPaths          []string `json:"ingest_paths"`
		EventFlow            []string `json:"event_flow"`
		ArchitectureControls []string `json:"architecture_controls"`
		Residuals            []string `json:"residuals"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode third-party scanning posture: %v", err)
	}
	if got.Capability != "CAP-SCAN-04" || !got.Served {
		t.Fatalf("capability/served = %q/%v, want CAP-SCAN-04/true", got.Capability, got.Served)
	}
	if got.MinimumRulesActive < 140 || got.Scanner == "" {
		t.Fatalf("scanner posture = %q/%d, want pinned scanner with 140+ rule floor", got.Scanner, got.MinimumRulesActive)
	}
	for _, want := range []string{"cicd_log", "container_registry", "slack", "jira"} {
		if !thirdPartyProviderListed(got.Providers, want) {
			t.Fatalf("providers missing %q: %+v", want, got.Providers)
		}
		if !containsString(got.IngestPaths, "/api/v1/secrets/scans/third-party/"+want+"/ingest") {
			t.Fatalf("ingest paths missing %q: %+v", want, got.IngestPaths)
		}
	}
	for _, want := range []string{"discovery.source.upserted", "discovery.run.queued", "discovery.finding.recorded", "discovery.run.completed"} {
		if !containsString(got.EventFlow, want) {
			t.Fatalf("event flow missing %q: %+v", want, got.EventFlow)
		}
	}
	for _, want := range []string{"AN-2", "AN-5", "AN-6", "AN-8"} {
		if !containsString(got.ArchitectureControls, want) {
			t.Fatalf("architecture controls missing %q: %+v", want, got.ArchitectureControls)
		}
	}
	if len(got.Residuals) == 0 {
		t.Fatalf("posture must expose residual shortfalls: %+v", got)
	}
}

func TestServedSecretWorkloadInjectionCAPSECR05(t *testing.T) {
	handler := api.New(nil, nil, nil, api.WithInsecureHeaderResolver())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/workload-injection", nil)
	req.Header.Set("X-Tenant-ID", "11111111-1111-1111-1111-111111111111")
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("workload injection status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got struct {
		Capability string `json:"capability"`
		Served     bool   `json:"served"`
		CRD        struct {
			Kind   string   `json:"kind"`
			Plural string   `json:"plural"`
			Owns   []string `json:"owns"`
		} `json:"crd"`
		Modes []struct {
			ID           string   `json:"id"`
			DeliveredBy  string   `json:"delivered_by"`
			Capabilities []string `json:"capabilities"`
		} `json:"modes"`
		WorkloadKinds        []string `json:"workload_kinds"`
		SidecarCommand       []string `json:"sidecar_command"`
		ArchitectureControls []string `json:"architecture_controls"`
		EvidenceRefs         []string `json:"evidence_refs"`
		Residuals            []string `json:"residuals"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode workload injection posture: %v", err)
	}
	if got.Capability != "CAP-SECR-05" || !got.Served {
		t.Fatalf("capability/served = %q/%v, want CAP-SECR-05/true", got.Capability, got.Served)
	}
	if got.CRD.Kind != "TrstctlSecretInjection" || got.CRD.Plural != "trstctlsecretinjections" {
		t.Fatalf("crd = %+v, want TrstctlSecretInjection/trstctlsecretinjections", got.CRD)
	}
	for _, want := range []string{"Deployment", "StatefulSet", "DaemonSet"} {
		if !containsString(got.WorkloadKinds, want) {
			t.Fatalf("workload kinds missing %q: %+v", want, got.WorkloadKinds)
		}
	}
	for _, want := range []string{"/usr/local/bin/trstctl-agent", "--secret-inject"} {
		if !containsString(got.SidecarCommand, want) {
			t.Fatalf("sidecar command missing %q: %+v", want, got.SidecarCommand)
		}
	}
	for _, want := range []string{"file", "env"} {
		if !injectionModeListed(got.Modes, want) {
			t.Fatalf("injection mode missing %q: %+v", want, got.Modes)
		}
	}
	for _, want := range []string{"AN-1", "AN-5", "AN-7", "AN-8"} {
		if !containsSubstring(got.ArchitectureControls, want) {
			t.Fatalf("architecture controls missing %q: %+v", want, got.ArchitectureControls)
		}
	}
	if len(got.EvidenceRefs) == 0 || len(got.Residuals) == 0 {
		t.Fatalf("posture must expose evidence and residuals: %+v", got)
	}
}

func TestRepoSecretScanWebhookRouteIsGuardedMutation(t *testing.T) {
	routes := api.New(nil, nil, nil).Routes()
	posture := findAPIRoute(routes, http.MethodGet, "/api/v1/secrets/scans/repositories")
	webhook := findAPIRoute(routes, http.MethodPost, "/api/v1/secrets/scans/repositories/{provider}/webhook")
	thirdPartyPosture := findAPIRoute(routes, http.MethodGet, "/api/v1/secrets/scans/third-party")
	thirdPartyIngest := findAPIRoute(routes, http.MethodPost, "/api/v1/secrets/scans/third-party/{provider}/ingest")
	workloadInjection := findAPIRoute(routes, http.MethodGet, "/api/v1/secrets/workload-injection")
	unvaulted := findAPIRoute(routes, http.MethodGet, "/api/v1/secrets/unvaulted")
	if posture.OperationID != "getSecretRepositoryScanning" || posture.Permission == "" || posture.Mutation {
		t.Fatalf("posture route = %+v, want read route with permission", posture)
	}
	if webhook.OperationID != "receiveSecretRepositoryWebhook" || webhook.Permission == "" || !webhook.Mutation {
		t.Fatalf("webhook route = %+v, want guarded mutation", webhook)
	}
	if thirdPartyPosture.OperationID != "getThirdPartySecretScanning" || thirdPartyPosture.Permission == "" || thirdPartyPosture.Mutation {
		t.Fatalf("third-party posture route = %+v, want read route with permission", thirdPartyPosture)
	}
	if thirdPartyIngest.OperationID != "ingestThirdPartySecretScan" || thirdPartyIngest.Permission == "" || !thirdPartyIngest.Mutation {
		t.Fatalf("third-party ingest route = %+v, want guarded mutation", thirdPartyIngest)
	}
	if workloadInjection.OperationID != "getSecretWorkloadInjection" || workloadInjection.Permission == "" || workloadInjection.Mutation {
		t.Fatalf("workload injection posture route = %+v, want read route with permission", workloadInjection)
	}
	if unvaulted.OperationID != "getUnvaultedSecretPosture" || unvaulted.Permission == "" || unvaulted.Mutation {
		t.Fatalf("unvaulted secret posture route = %+v, want read route with permission", unvaulted)
	}
}

func providerListed(providers []struct {
	ID               string   `json:"id"`
	RealtimeTriggers []string `json:"realtime_triggers"`
	IngestMode       string   `json:"ingest_mode"`
	OutboxMode       string   `json:"outbox_mode"`
}, want string) bool {
	for _, p := range providers {
		if p.ID == want && len(p.RealtimeTriggers) > 0 && p.IngestMode != "" && p.OutboxMode != "" {
			return true
		}
	}
	return false
}

func gateRequired(gates []struct {
	ID       string `json:"id"`
	Required bool   `json:"required"`
}, want string) bool {
	for _, g := range gates {
		if g.ID == want && g.Required {
			return true
		}
	}
	return false
}

func thirdPartyProviderListed(providers []struct {
	ID            string   `json:"id"`
	ArtifactKinds []string `json:"artifact_kinds"`
	IngestMode    string   `json:"ingest_mode"`
	OutboxMode    string   `json:"outbox_mode"`
}, want string) bool {
	for _, p := range providers {
		if p.ID == want && len(p.ArtifactKinds) > 0 && p.IngestMode != "" && p.OutboxMode != "" {
			return true
		}
	}
	return false
}

func injectionModeListed(modes []struct {
	ID           string   `json:"id"`
	DeliveredBy  string   `json:"delivered_by"`
	Capabilities []string `json:"capabilities"`
}, want string) bool {
	for _, mode := range modes {
		if mode.ID == want && mode.DeliveredBy != "" && len(mode.Capabilities) > 0 {
			return true
		}
	}
	return false
}

func containsSubstring(values []string, want string) bool {
	for _, value := range values {
		if strings.Contains(value, want) {
			return true
		}
	}
	return false
}

func findAPIRoute(routes []api.Route, method, path string) api.Route {
	for _, rt := range routes {
		if rt.Method == method && rt.Path == path {
			return rt
		}
	}
	return api.Route{}
}
