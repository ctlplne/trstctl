// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/api"
)

func TestCapabilitiesPAMRequestNeedsConfiguredBroker(t *testing.T) {
	response := httptest.NewRecorder()
	api.New(nil, nil, nil, api.WithInsecureHeaderResolver()).ServeHTTP(response,
		capabilityViewRequest("11111111-1111-4111-8111-111111111111", "admin"))
	if response.Code != http.StatusOK {
		t.Fatalf("capabilities: %d %s", response.Code, response.Body.String())
	}
	var view capabilityViewTestResponse
	if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	for _, operationID := range []string{"requestPAMSession", "openPAMSession", "listPAMSessions", "getPAMSession"} {
		operation, ok := findRuntimeOperation(view, operationID)
		if !ok || operation.State != "unavailable" || operation.Code != "dependency_not_configured" {
			t.Fatalf("%s posture = %+v, want configured-broker refusal", operationID, operation)
		}
	}
}
