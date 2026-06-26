package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/aimodel"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
)

func TestAIModelFromConfigBuildsLocalAdapter(t *testing.T) {
	var seen struct {
		Model  string `json:"model"`
		Prompt string `json:"prompt"`
	}
	modelEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Fatalf("decode model request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"response": "from local model"})
	}))
	defer modelEndpoint.Close()

	adapter, status, err := aiModelFromConfig(config.AIModel{
		Mode:     config.AIModelLocal,
		Runtime:  config.AIModelRuntimeOllama,
		Endpoint: modelEndpoint.URL,
		Name:     "llama3.1",
	}, nil)
	if err != nil {
		t.Fatalf("aiModelFromConfig: %v", err)
	}
	if adapter == nil || !adapter.Available() {
		t.Fatal("local model config did not build an available adapter")
	}
	if status.Mode != config.AIModelLocal || status.Runtime != config.AIModelRuntimeOllama || status.Egress != "local-endpoint" || status.EndpointHost == "" {
		t.Fatalf("bad status: %+v", status)
	}
	out, err := adapter.Reason(context.Background(), "password=hunter2 summarize")
	if err != nil {
		t.Fatalf("adapter Reason: %v", err)
	}
	if out != "from local model" {
		t.Fatalf("answer = %q", out)
	}
	if seen.Model != "llama3.1" || strings.Contains(seen.Prompt, "hunter2") {
		t.Fatalf("bad/redaction-missing model request: %+v", seen)
	}
}

// TestAIModelFromConfigPIIEgressPolicy is the PRIVACY-005 served-wiring acceptance:
// the config flags allow_pii/block_pii build an adapter whose Reason path redacts
// (default), blocks, or preserves personal/identifying data before the configured
// model endpoint (the egress boundary) ever sees the prompt, and the status reports
// the posture. It proves the policy is wired into the served path, not just the
// library. (No embedded PostgreSQL: this exercises aiModelFromConfig directly.)
func TestAIModelFromConfigPIIEgressPolicy(t *testing.T) {
	var seenPrompt string
	modelEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Prompt string `json:"prompt"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		seenPrompt = body.Prompt
		_ = json.NewEncoder(w).Encode(map[string]string{"response": "ok"})
	}))
	defer modelEndpoint.Close()

	const piiPrompt = "owner alice.smith@corp.example.com on svc-api.payments.prod.internal at 203.0.113.42"

	// Default: default-private. PII must NOT reach the model endpoint, and status
	// reports pii_egress=redact.
	defAdapter, defStatus, err := aiModelFromConfig(config.AIModel{
		Mode: config.AIModelLocal, Runtime: config.AIModelRuntimeOllama,
		Endpoint: modelEndpoint.URL, Name: "llama3.1",
	}, nil)
	if err != nil {
		t.Fatalf("aiModelFromConfig default: %v", err)
	}
	if defStatus.PIIEgress != "redact" {
		t.Fatalf("default PIIEgress = %q, want redact", defStatus.PIIEgress)
	}
	seenPrompt = ""
	if _, err := defAdapter.Reason(context.Background(), piiPrompt); err != nil {
		t.Fatalf("default Reason: %v", err)
	}
	for _, pii := range []string{"alice.smith@corp.example.com", "svc-api.payments.prod.internal", "203.0.113.42"} {
		if strings.Contains(seenPrompt, pii) {
			t.Fatalf("default-private leaked PII %q to model: %q", pii, seenPrompt)
		}
	}

	// allow_pii=true: explicit operator consent. PII is preserved for egress and
	// status reports pii_egress=allow.
	allowAdapter, allowStatus, err := aiModelFromConfig(config.AIModel{
		Mode: config.AIModelLocal, Runtime: config.AIModelRuntimeOllama,
		Endpoint: modelEndpoint.URL, Name: "llama3.1", AllowPII: true,
	}, nil)
	if err != nil {
		t.Fatalf("aiModelFromConfig allow_pii: %v", err)
	}
	if allowStatus.PIIEgress != "allow" {
		t.Fatalf("allow_pii PIIEgress = %q, want allow", allowStatus.PIIEgress)
	}
	seenPrompt = ""
	if _, err := allowAdapter.Reason(context.Background(), piiPrompt); err != nil {
		t.Fatalf("allow_pii Reason: %v", err)
	}
	if !strings.Contains(seenPrompt, "alice.smith@corp.example.com") {
		t.Fatalf("allow_pii should preserve PII for egress, model saw: %q", seenPrompt)
	}

	// block_pii=true: strict fail-closed. The send is refused and the model is not
	// reached; status reports pii_egress=block.
	blockAdapter, blockStatus, err := aiModelFromConfig(config.AIModel{
		Mode: config.AIModelLocal, Runtime: config.AIModelRuntimeOllama,
		Endpoint: modelEndpoint.URL, Name: "llama3.1", BlockPII: true,
	}, nil)
	if err != nil {
		t.Fatalf("aiModelFromConfig block_pii: %v", err)
	}
	if blockStatus.PIIEgress != "block" {
		t.Fatalf("block_pii PIIEgress = %q, want block", blockStatus.PIIEgress)
	}
	seenPrompt = ""
	if _, err := blockAdapter.Reason(context.Background(), piiPrompt); !errors.Is(err, aimodel.ErrPIIBlocked) {
		t.Fatalf("block_pii Reason err = %v, want ErrPIIBlocked", err)
	}
	if seenPrompt != "" {
		t.Fatalf("block_pii reached the model despite the block gate: %q", seenPrompt)
	}
}

func TestServedAIStatusReportsDisabledAndConfiguredPosture(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	tok := seedScopedToken(t, h.store, h.tenant, "graph:read")
	statusCode, body := aiReq(t, h, http.MethodGet, "/api/v1/ai/status", tok, nil)
	if statusCode != http.StatusOK {
		t.Fatalf("disabled AI status: status %d body %s", statusCode, body)
	}
	var disabled struct {
		Enabled             bool   `json:"enabled"`
		ModelConfigured     bool   `json:"model_configured"`
		ModelMode           string `json:"model_mode"`
		Egress              string `json:"egress"`
		ResidualRefusalGate bool   `json:"residual_refusal_gate"`
	}
	if err := json.Unmarshal(body, &disabled); err != nil {
		t.Fatalf("decode disabled status: %v", err)
	}
	if disabled.Enabled || disabled.ModelConfigured || disabled.ModelMode != "off" || disabled.Egress != "none" || !disabled.ResidualRefusalGate {
		t.Fatalf("bad disabled status: %+v body %s", disabled, body)
	}

	h = newServedHarness(t, config.Protocols{}, withAIEnabled(), func(d *Deps) {
		d.AIModel = aimodel.New(servedStatusModel{}, nil)
		d.AIModelStatus = api.AIModelStatus{
			Mode:         config.AIModelLocal,
			Runtime:      config.AIModelRuntimeOllama,
			ModelName:    "llama3.1",
			EndpointHost: "127.0.0.1:11434",
			Egress:       "local-endpoint",
		}
	})
	tok = seedScopedToken(t, h.store, h.tenant, "graph:read")
	statusCode, body = aiReq(t, h, http.MethodGet, "/api/v1/ai/status", tok, nil)
	if statusCode != http.StatusOK {
		t.Fatalf("configured AI status: status %d body %s", statusCode, body)
	}
	var configured struct {
		Enabled           bool   `json:"enabled"`
		ModelConfigured   bool   `json:"model_configured"`
		ModelMode         string `json:"model_mode"`
		ModelName         string `json:"model_name"`
		Runtime           string `json:"runtime"`
		EndpointHost      string `json:"endpoint_host"`
		Egress            string `json:"egress"`
		RateMax           int    `json:"rate_max"`
		RateWindowSeconds int    `json:"rate_window_seconds"`
	}
	if err := json.Unmarshal(body, &configured); err != nil {
		t.Fatalf("decode configured status: %v", err)
	}
	if !configured.Enabled || !configured.ModelConfigured || configured.ModelMode != "local" || configured.ModelName != "llama3.1" ||
		configured.Runtime != "ollama" || configured.EndpointHost != "127.0.0.1:11434" || configured.Egress != "local-endpoint" ||
		configured.RateMax != 3 || configured.RateWindowSeconds != 60 {
		t.Fatalf("bad configured status: %+v body %s", configured, body)
	}
}

type servedStatusModel struct{}

func (servedStatusModel) Name() string { return "local:ollama" }

func (servedStatusModel) Complete(context.Context, string) (string, error) { return "ok", nil }
