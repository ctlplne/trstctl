package problem_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/api/problem"
)

func TestMarshalRFCShape(t *testing.T) {
	p := problem.New(http.StatusBadRequest, "missing field 'name'").
		WithType("https://trstctl.com/problems/validation").
		WithInstance("/api/v1/certs/123")

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if m["type"] != "https://trstctl.com/problems/validation" {
		t.Errorf("type = %v", m["type"])
	}
	if m["title"] != http.StatusText(http.StatusBadRequest) {
		t.Errorf("title = %v", m["title"])
	}
	if m["status"] != float64(http.StatusBadRequest) {
		t.Errorf("status = %v", m["status"])
	}
	if m["detail"] != "missing field 'name'" {
		t.Errorf("detail = %v", m["detail"])
	}
	if m["instance"] != "/api/v1/certs/123" {
		t.Errorf("instance = %v", m["instance"])
	}
}

func TestDefaultTypeIsAboutBlank(t *testing.T) {
	data, err := json.Marshal(problem.New(http.StatusNotFound, ""))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if m["type"] != "about:blank" {
		t.Errorf("default type should be about:blank, got %v", m["type"])
	}
}

// TestRoundTrip proves marshal -> unmarshal -> marshal is stable and that
// extension members survive the trip.
func TestRoundTrip(t *testing.T) {
	orig := problem.New(http.StatusConflict, "already exists").
		WithType("https://trstctl.com/problems/conflict").
		WithInstance("/api/v1/tenants/acme").
		WithExtension("trace_id", "abc-123").
		WithExtension("retry_after_seconds", 30)

	b1, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var got problem.Problem
	if err := json.Unmarshal(b1, &got); err != nil {
		t.Fatal(err)
	}
	b2, err := json.Marshal(&got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1, b2) {
		t.Errorf("round-trip changed JSON:\n  before: %s\n  after:  %s", b1, b2)
	}
	if got.Status != http.StatusConflict || got.Title != http.StatusText(http.StatusConflict) {
		t.Errorf("standard members not restored: %+v", got)
	}
	if got.Extensions["trace_id"] != "abc-123" {
		t.Errorf("extension trace_id not restored: %v", got.Extensions["trace_id"])
	}
}

func TestWriteSetsHeaderAndStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	p := problem.New(http.StatusUnprocessableEntity, "bad input")
	if err := p.Write(rec); err != nil {
		t.Fatal(err)
	}
	if ct := rec.Header().Get("Content-Type"); ct != problem.MediaType {
		t.Errorf("Content-Type = %q, want %q", ct, problem.MediaType)
	}
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnprocessableEntity)
	}
	var got problem.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != http.StatusUnprocessableEntity {
		t.Errorf("body status = %d", got.Status)
	}
}

func TestErrorImplementsError(t *testing.T) {
	var err error = problem.New(http.StatusInternalServerError, "boom")
	if err.Error() == "" {
		t.Error("Error() should be non-empty")
	}
}
