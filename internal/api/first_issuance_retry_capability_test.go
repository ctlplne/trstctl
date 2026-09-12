// SPDX-License-Identifier: MPL-2.0

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/store"
)

type capabilityFirstIssuanceRetry struct{}

func (capabilityFirstIssuanceRetry) RetryFirstIssuance(context.Context, string, string, string, string, string) (store.FirstIssuanceRetryReceipt, error) {
	return store.FirstIssuanceRetryReceipt{}, store.ErrIssuanceRetryUnavailable
}
func (capabilityFirstIssuanceRetry) FirstIssuanceRetryReadiness(context.Context, string, string, string) (api.FirstIssuanceRetryReadiness, error) {
	return api.FirstIssuanceRetryReadiness{}, nil
}

func TestCapabilitiesFirstIssuanceRecoveryNeedsServiceAndIssuancePermission(t *testing.T) {
	for _, tc := range []struct {
		name, role, state string
		configured        bool
	}{
		{"missing service", "admin", "unavailable", false},
		{"reader", "viewer", "denied", true},
		{"issuer", "admin", "allowed", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := []api.Option{api.WithInsecureHeaderResolver()}
			if tc.configured {
				opts = append(opts, api.WithFirstIssuanceRetry(capabilityFirstIssuanceRetry{}))
			}
			response := httptest.NewRecorder()
			api.New(nil, nil, nil, opts...).ServeHTTP(response, capabilityViewRequest("11111111-1111-4111-8111-111111111111", tc.role))
			if response.Code != http.StatusOK {
				t.Fatalf("capabilities: %d %s", response.Code, response.Body.String())
			}
			var view capabilityViewTestResponse
			if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
				t.Fatal(err)
			}
			operation, ok := findRuntimeOperation(view, "retryFirstIssuance")
			if !ok || operation.State != tc.state {
				t.Fatalf("recovery posture: %+v, want %s", operation, tc.state)
			}
			if !tc.configured {
				action := findUnavailableCapabilityAction(t, findCapabilityViewItem(t, view, "F4"), "retryFirstIssuance")
				if action.Code != "dependency_not_configured" {
					t.Fatalf("missing recovery dependency: %+v", action)
				}
			}
		})
	}
}
