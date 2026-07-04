// SPDX-License-Identifier: MPL-2.0

package aimodel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// FormatOllama posts the native Ollama generate request shape.
	FormatOllama = "ollama"
	// FormatOpenAIChat posts the OpenAI-compatible chat completion shape used by
	// vLLM and by most operator-owned cloud gateways.
	FormatOpenAIChat = "openai-chat"
)

// HTTPCompleter is the production Completer for local Ollama/vLLM endpoints and
// operator-owned cloud gateways. It carries no credentials by design; every prompt
// must already have crossed Adapter.Reason's redaction and residual-secret gate.
type HTTPCompleter struct {
	Endpoint string
	Model    string
	Format   string
	Client   *http.Client
	Timeout  time.Duration
}

// NewHTTPCompleter constructs a completion client. The endpoint is the exact
// completion URL to POST to; config validation owns URL safety before boot.
func NewHTTPCompleter(endpoint, model, format string, client *http.Client) *HTTPCompleter {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if format == "" {
		format = FormatOpenAIChat
	}
	return &HTTPCompleter{Endpoint: endpoint, Model: model, Format: format, Client: client, Timeout: 30 * time.Second}
}

// Do implements Completer.
func (c *HTTPCompleter) Do(ctx context.Context, prompt string) (string, error) {
	if c == nil || c.Client == nil {
		return "", fmt.Errorf("aimodel: HTTP completer is not configured")
	}
	body, err := c.requestBody(prompt)
	if err != nil {
		return "", err
	}
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("aimodel: build model request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("aimodel: model request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("aimodel: model endpoint returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("aimodel: read model response: %w", err)
	}
	return c.responseText(data)
}

func (c *HTTPCompleter) requestBody(prompt string) ([]byte, error) {
	switch c.Format {
	case FormatOllama:
		return json.Marshal(struct {
			Model  string `json:"model"`
			Prompt string `json:"prompt"`
			Stream bool   `json:"stream"`
		}{Model: c.Model, Prompt: prompt, Stream: false})
	case FormatOpenAIChat:
		return json.Marshal(struct {
			Model    string        `json:"model"`
			Messages []chatMessage `json:"messages"`
			Stream   bool          `json:"stream"`
		}{
			Model: c.Model,
			Messages: []chatMessage{
				{Role: "user", Content: prompt},
			},
			Stream: false,
		})
	default:
		return nil, fmt.Errorf("aimodel: unknown HTTP completion format %q", c.Format)
	}
}

func (c *HTTPCompleter) responseText(data []byte) (string, error) {
	switch c.Format {
	case FormatOllama:
		var out struct {
			Response string `json:"response"`
			Error    string `json:"error"`
		}
		if err := json.Unmarshal(data, &out); err != nil {
			return "", fmt.Errorf("aimodel: decode Ollama response: %w", err)
		}
		if out.Error != "" {
			return "", fmt.Errorf("aimodel: Ollama response error: %s", out.Error)
		}
		if strings.TrimSpace(out.Response) == "" {
			return "", fmt.Errorf("aimodel: Ollama response contained no text")
		}
		return out.Response, nil
	case FormatOpenAIChat:
		var out struct {
			Choices []struct {
				Message chatMessage `json:"message"`
				Text    string      `json:"text"`
			} `json:"choices"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(data, &out); err != nil {
			return "", fmt.Errorf("aimodel: decode chat response: %w", err)
		}
		if out.Error != nil && out.Error.Message != "" {
			return "", fmt.Errorf("aimodel: chat response error: %s", out.Error.Message)
		}
		for _, choice := range out.Choices {
			if strings.TrimSpace(choice.Message.Content) != "" {
				return choice.Message.Content, nil
			}
			if strings.TrimSpace(choice.Text) != "" {
				return choice.Text, nil
			}
		}
		return "", fmt.Errorf("aimodel: chat response contained no text")
	default:
		return "", fmt.Errorf("aimodel: unknown HTTP completion format %q", c.Format)
	}
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
