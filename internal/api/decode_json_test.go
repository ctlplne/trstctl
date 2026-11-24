// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/inputtext"
)

func TestRejectsOversizedJSONBody(t *testing.T) {
	body := `{"value":"` + strings.Repeat("x", int(defaultRESTJSONBodyLimit)) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/test", strings.NewReader(body))

	var dst map[string]any
	err := decodeJSON(req, &dst)
	var ae *apiError
	if !errors.As(err, &ae) {
		t.Fatalf("decodeJSON error = %v, want apiError", err)
	}
	if ae.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("decodeJSON status = %d, want 413", ae.status)
	}
	if !strings.Contains(ae.detail, "too large") {
		t.Fatalf("decodeJSON detail = %q, want too large", ae.detail)
	}

	api := New(nil, nil, nil, WithInsecureHeaderResolver(), WithAISurface(AISurfaceBackend{}))
	req = httptest.NewRequest(http.MethodPost, "/api/v1/ai/query", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "11111111-1111-1111-1111-111111111111")
	req.Header.Set("X-Subject", "sec-002-test")
	req.Header.Set("X-Roles", "admin")
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("served oversized JSON status = %d, want 413: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "application/problem+json") {
		t.Fatalf("served oversized JSON content-type = %q, want problem+json", got)
	}
}

func TestUnsafeEventTextMapsToClientError(t *testing.T) {
	a := New(nil, nil, nil)
	for _, cause := range []error{inputtext.ErrNUL, inputtext.ErrInvalidUTF8} {
		rec := httptest.NewRecorder()
		a.writeError(rec, fmt.Errorf("event admission: %w", cause))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unsafe text") {
			t.Errorf("%v mapped to %d %s, want 400 unsafe text", cause, rec.Code, rec.Body.String())
		}
	}
}

func TestDecodeJSONRejectsTrailingTokens(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/test", strings.NewReader(`{"value":"one"} {"value":"two"}`))

	var dst map[string]any
	err := decodeJSON(req, &dst)
	var ae *apiError
	if !errors.As(err, &ae) {
		t.Fatalf("decodeJSON error = %v, want apiError", err)
	}
	if ae.status != http.StatusBadRequest {
		t.Fatalf("decodeJSON status = %d, want 400", ae.status)
	}
	if !strings.Contains(ae.detail, "multiple JSON values") {
		t.Fatalf("decodeJSON detail = %q, want trailing-token message", ae.detail)
	}
}
