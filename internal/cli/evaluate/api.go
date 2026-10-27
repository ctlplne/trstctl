// SPDX-License-Identifier: BUSL-1.1

package evaluate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// maxResponseBytes bounds one API response; an audit export is the largest.
const maxResponseBytes = 16 << 20

// apiClient calls the control plane's own API as the evaluating operator.
type apiClient struct {
	base  string
	token string
	http  *http.Client
}

// apiError is a refused or failed API call, with the server's own words.
type apiError struct {
	Method, Path string
	Status       int
	Detail       string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("%s %s answered %d: %s", e.Method, e.Path, e.Status, e.Detail)
}

func (c *apiClient) do(ctx context.Context, method, path string, body any, idempotencyKey string) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	return c.send(req, method, path)
}

func (c *apiClient) send(req *http.Request, method, path string) ([]byte, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("%s %s: read response: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &apiError{Method: method, Path: path, Status: resp.StatusCode, Detail: problemDetail(data)}
	}
	return data, nil
}

func (c *apiClient) get(ctx context.Context, path string, out any) error {
	data, err := c.do(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return err
	}
	return decode(path, data, out)
}

func (c *apiClient) post(ctx context.Context, path string, body any, idempotencyKey string, out any) error {
	data, err := c.do(ctx, http.MethodPost, path, body, idempotencyKey)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	return decode(path, data, out)
}

// postRaw sends a binary body, such as an OCSP request, to an absolute URL or
// an API path.
func (c *apiClient) postRaw(ctx context.Context, url, contentType string, body []byte) ([]byte, error) {
	target := url
	if strings.HasPrefix(url, "/") {
		target = c.base + url
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.send(req, http.MethodPost, url)
}

func decode(path string, data []byte, out any) error {
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

// problemDetail is the RFC 7807 detail of a refusal, or the start of the body.
func problemDetail(data []byte) string {
	var problem struct {
		Title  string `json:"title"`
		Detail string `json:"detail"`
	}
	if json.Unmarshal(data, &problem) == nil && (problem.Detail != "" || problem.Title != "") {
		if problem.Detail != "" {
			return problem.Detail
		}
		return problem.Title
	}
	text := strings.TrimSpace(string(data))
	if len(text) > 300 {
		text = text[:300] + "..."
	}
	return text
}
