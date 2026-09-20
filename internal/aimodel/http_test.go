// SPDX-License-Identifier: BUSL-1.1

package aimodel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPCompleterOllamaShapeUsesRedactedPrompt(t *testing.T) {
	var seen struct {
		Model  string `json:"model"`
		Prompt string `json:"prompt"`
		Stream bool   `json:"stream"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("model request must not synthesize an auth header from config, got %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"response": "local answer"})
	}))
	defer srv.Close()

	completer := NewHTTPCompleter(srv.URL, "llama3.1", FormatOllama, srv.Client())
	model := New(LocalModel{Runtime: "ollama", Client: completer}, nil)
	out, err := model.Reason(context.Background(), "password=hunter2 explain the renewal")
	if err != nil {
		t.Fatalf("Reason through Ollama completer: %v", err)
	}
	if out != "local answer" {
		t.Fatalf("answer = %q", out)
	}
	if seen.Model != "llama3.1" || seen.Stream {
		t.Fatalf("bad Ollama request shape: %+v", seen)
	}
	if strings.Contains(seen.Prompt, "hunter2") || !strings.Contains(seen.Prompt, "[REDACTED") {
		t.Fatalf("prompt was not redacted before HTTP egress: %q", seen.Prompt)
	}
}

func TestHTTPCompleterOpenAICompatibleShape(t *testing.T) {
	var seen struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
		Stream bool `json:"stream"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"role": "assistant", "content": "gateway answer"}},
			},
		})
	}))
	defer srv.Close()

	completer := NewHTTPCompleter(srv.URL, "ops-model", FormatOpenAIChat, srv.Client())
	model := New(CloudModel{Provider: "gateway", Client: completer}, nil)
	out, err := model.Reason(context.Background(), "client_secret = verysecretvalue")
	if err != nil {
		t.Fatalf("Reason through OpenAI-compatible completer: %v", err)
	}
	if out != "gateway answer" {
		t.Fatalf("answer = %q", out)
	}
	if seen.Model != "ops-model" || seen.Stream || len(seen.Messages) != 1 || seen.Messages[0].Role != "user" {
		t.Fatalf("bad chat request shape: %+v", seen)
	}
	if strings.Contains(seen.Messages[0].Content, "verysecretvalue") || !strings.Contains(seen.Messages[0].Content, "[REDACTED") {
		t.Fatalf("prompt was not redacted before HTTP egress: %q", seen.Messages[0].Content)
	}
}
