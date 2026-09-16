// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSCIMPersistenceFailureIsRetryableAndSanitized(t *testing.T) {
	recorder := httptest.NewRecorder()
	(&providerSCIMHandler{}).writeMutationError(recorder, fmt.Errorf("%w: internal event-storage detail", ErrMutationPersistence))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("server persistence failure was attributed to invalid SCIM input: %d", recorder.Code)
	}
	var result struct {
		Status   string `json:"status"`
		SCIMType string `json:"scimType"`
		Detail   string `json:"detail"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "500" || result.SCIMType != "" || !strings.Contains(result.Detail, "retry the same command") || strings.Contains(result.Detail, "internal event-storage") {
		t.Fatalf("SCIM failure is not a sanitized retryable server response: %+v", result)
	}
}
