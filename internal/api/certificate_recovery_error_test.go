// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/store"
)

func TestCertificateRecoveryRefusalNamesRecoveryWithoutLeakingInternalContext(t *testing.T) {
	a := New(nil, nil, nil)
	rec := httptest.NewRecorder()
	a.writeError(rec, fmt.Errorf("private-context-marker: %w", store.ErrCertificateRecordingRebuildRequired))
	var body struct {
		Status    int    `json:"status"`
		Detail    string `json:"detail"`
		Recovery  string `json:"recovery_required"`
		Retryable *bool  `json:"retryable"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusServiceUnavailable || body.Status != rec.Code || body.Recovery != "read_model_rebuild" || body.Retryable == nil || *body.Retryable {
		t.Fatalf("wrong recovery refusal: status=%d body=%+v", rec.Code, body)
	}
	if rec.Header().Get("Retry-After") != "" || strings.Contains(rec.Body.String(), "private-context-marker") ||
		!strings.Contains(body.Detail, "stop mutating control-plane replicas") || !strings.Contains(body.Detail, "trstctl --rebuild") ||
		!strings.Contains(body.Detail, "same Idempotency-Key") {
		t.Fatalf("unsafe or missing recovery guidance: %s", rec.Body.String())
	}
}
