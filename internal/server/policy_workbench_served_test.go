package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestServedPolicyDryRunWorkbenchTRACE009(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "policy-author@example.test", "policy:write")

	body := map[string]any{
		"kind": "lifecycle",
		"module": `package trstctl.policy

default allow := false
default reason := ""

allow if {
	input.action == "issue"
	input.profile == "tls-server"
}

reason := "only tls-server issue is allowed in this candidate" if {
	not allow
}`,
		"input": map[string]any{
			"tenant_id": "attacker-tenant-is-overridden",
			"action":    "issue",
			"profile":   "tls-server",
			"subject":   "payments-api",
		},
		"trace_limit": 20,
	}
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/policy/dry-run", tok, "trace-009-policy-dry-run", body)
	if status != http.StatusOK {
		t.Fatalf("policy dry-run: status %d body %s", status, raw)
	}
	var got struct {
		Kind         string `json:"kind"`
		Valid        bool   `json:"valid"`
		Allow        bool   `json:"allow"`
		Deny         bool   `json:"deny"`
		ModuleSHA256 string `json:"module_sha256"`
		AuditEvent   string `json:"audit_event"`
		InputSummary struct {
			TenantID string `json:"tenant_id"`
			Actor    string `json:"actor"`
			Action   string `json:"action"`
			Profile  string `json:"profile"`
		} `json:"input_summary"`
		Trace []struct {
			Op   string `json:"op"`
			Node string `json:"node"`
		} `json:"trace"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode policy dry-run response: %v body=%s", err, raw)
	}
	if got.Kind != "lifecycle" || !got.Valid || !got.Allow || got.Deny || got.ModuleSHA256 == "" {
		t.Fatalf("policy dry-run result = %+v, want valid lifecycle allow", got)
	}
	if got.AuditEvent != "policy.dry_run.evaluated" || !h.hasEvent(t, "policy.dry_run.evaluated") {
		t.Fatalf("policy dry-run audit event missing: response=%q", got.AuditEvent)
	}
	if got.InputSummary.TenantID != h.tenant || got.InputSummary.Actor != "policy-author@example.test" || got.InputSummary.Action != "issue" || got.InputSummary.Profile != "tls-server" {
		t.Fatalf("input summary = %+v, want authenticated tenant/actor and lifecycle fields", got.InputSummary)
	}
	if len(got.Trace) == 0 {
		t.Fatal("policy dry-run returned no trace rows")
	}
	for _, row := range got.Trace {
		if bytes.Contains([]byte(row.Node), []byte("payments-api")) {
			t.Fatalf("policy trace leaked plugged input value in row %+v", row)
		}
	}
	status, replay := secretsReqKey(t, h, http.MethodPost, "/api/v1/policy/dry-run", tok, "trace-009-policy-dry-run", body)
	if status != http.StatusOK {
		t.Fatalf("policy dry-run replay: status %d body %s", status, replay)
	}
	if !bytes.Equal(raw, replay) {
		t.Fatalf("policy dry-run replay did not return cached body\nfirst=%s\nreplay=%s", raw, replay)
	}
}
