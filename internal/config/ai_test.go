// SPDX-License-Identifier: MPL-2.0

package config

import (
	"strings"
	"testing"
)

func TestAIModelDefaultsOff(t *testing.T) {
	cfg := Default()
	if cfg.AI.Model.ModeValue() != AIModelOff {
		t.Fatalf("default AI model mode = %q, want %q", cfg.AI.Model.ModeValue(), AIModelOff)
	}
	if cfg.AI.Model.AllowEgress {
		t.Fatal("default AI model must not allow egress")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config should validate with AI model off: %v", err)
	}
}

func TestAIModelEnvOverrides(t *testing.T) {
	env := map[string]string{
		"TRSTCTL_AI_ENABLE_API":          "true",
		"TRSTCTL_AI_MODEL_MODE":          "local",
		"TRSTCTL_AI_MODEL_RUNTIME":       "ollama",
		"TRSTCTL_AI_MODEL_ENDPOINT":      "http://127.0.0.1:11434/api/generate",
		"TRSTCTL_AI_MODEL_NAME":          "llama3.1",
		"TRSTCTL_AI_RATE_MAX":            "7",
		"TRSTCTL_AI_RATE_WINDOW_SECONDS": "11",
		"TRSTCTL_AI_MCP_IDENTITY":        "spiffe://example.org/mcp-server",
		"TRSTCTL_AI_MCP_WRITE_TOOLS":     "true",
	}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load local AI model env: %v", err)
	}
	if !cfg.AI.EnableAPI || cfg.AI.Model.ModeValue() != AIModelLocal || cfg.AI.Model.Runtime != AIModelRuntimeOllama {
		t.Fatalf("AI env not applied: %+v", cfg.AI)
	}
	if cfg.AI.Model.Endpoint != "http://127.0.0.1:11434/api/generate" || cfg.AI.Model.Name != "llama3.1" {
		t.Fatalf("AI model endpoint/name env not applied: %+v", cfg.AI.Model)
	}
	if cfg.AI.RateMax != 7 || cfg.AI.RateWindowSeconds != 11 || cfg.AI.MCPIdentity == "" || !cfg.AI.MCPWriteTools {
		t.Fatalf("AI rate/MCP env not applied: %+v", cfg.AI)
	}
}

func TestAIModelCloudRequiresExplicitHTTPSEgress(t *testing.T) {
	c := Default()
	c.AI.Model = AIModel{Mode: AIModelCloud, Provider: "gateway", Endpoint: "https://llm.example.com/v1/chat/completions", Name: "ops-model"}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "allow_egress=true") {
		t.Fatalf("cloud model without explicit egress should fail, got %v", err)
	}

	c.AI.Model.AllowEgress = true
	if err := c.Validate(); err != nil {
		t.Fatalf("cloud model with explicit HTTPS egress should validate: %v", err)
	}

	c.AI.Model.Endpoint = "http://llm.example.com/v1/chat/completions"
	err = c.Validate()
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("cloud model over plaintext HTTP should fail, got %v", err)
	}
}

func TestAIModelLocalAllowsOnlyLoopbackHTTP(t *testing.T) {
	c := Default()
	c.AI.Model = AIModel{Mode: AIModelLocal, Runtime: AIModelRuntimeOllama, Endpoint: "http://127.0.0.1:11434/api/generate", Name: "llama3.1"}
	if err := c.Validate(); err != nil {
		t.Fatalf("loopback local HTTP model should validate: %v", err)
	}

	c.AI.Model.Endpoint = "http://ollama.internal:11434/api/generate"
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("non-loopback local HTTP model should fail, got %v", err)
	}

	c.AI.Model.Endpoint = "https://ollama.internal/api/generate"
	if err := c.Validate(); err != nil {
		t.Fatalf("HTTPS local model endpoint should validate: %v", err)
	}
}

func TestAIModelRejectsURLCredentials(t *testing.T) {
	c := Default()
	c.AI.Model = AIModel{Mode: AIModelCloud, Provider: "gateway", Endpoint: "https://user:pass@llm.example.com/v1/chat/completions", Name: "ops-model", AllowEgress: true}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "must not include credentials") {
		t.Fatalf("model endpoint with URL credentials should fail, got %v", err)
	}
}
