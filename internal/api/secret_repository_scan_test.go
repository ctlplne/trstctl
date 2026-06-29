package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestRepoSecretScanWebhookRouteIsGuardedMutation(t *testing.T) {
	routes := api.New(nil, nil, nil).Routes()
	posture := findAPIRoute(routes, http.MethodGet, "/api/v1/secrets/scans/repositories")
	webhook := findAPIRoute(routes, http.MethodPost, "/api/v1/secrets/scans/repositories/{provider}/webhook")
	if posture.OperationID != "getSecretRepositoryScanning" || posture.Permission == "" || posture.Mutation {
		t.Fatalf("posture route = %+v, want read route with permission", posture)
	}
	if webhook.OperationID != "receiveSecretRepositoryWebhook" || webhook.Permission == "" || !webhook.Mutation {
		t.Fatalf("webhook route = %+v, want guarded mutation", webhook)
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

func findAPIRoute(routes []api.Route, method, path string) api.Route {
	for _, rt := range routes {
		if rt.Method == method && rt.Path == path {
			return rt
		}
	}
	return api.Route{}
}
