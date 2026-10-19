// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/events"
)

func TestCAHierarchyEventIdentityIndexCatchUpIsRetryable(t *testing.T) {
	a := New(nil, nil, nil)
	rec := httptest.NewRecorder()
	a.writeError(rec, fmt.Errorf("index covered 392964 of 395348: %w", events.ErrEventIDIndexBehind))
	var body struct {
		Status int    `json:"status"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusServiceUnavailable || body.Status != rec.Code || rec.Header().Get("Retry-After") != "1" {
		t.Fatalf("index catch-up response = %d header=%v body=%s; want 503 and Retry-After", rec.Code, rec.Header(), rec.Body.String())
	}
	if !strings.Contains(body.Detail, "same Idempotency-Key") || strings.Contains(body.Detail, "392964") {
		t.Fatalf("index catch-up detail does not guide safe retry or leaks source position: %q", body.Detail)
	}
}
