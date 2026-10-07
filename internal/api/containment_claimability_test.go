// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
)

// A reviewed emergency response must not say it can stop a host when the
// operator has not enabled that exact agent job kind. The incident originally
// passed review, revoked the CA certificates, and left the compromised leaf
// served with an unclaimable containment job.
func TestContainmentPreviewsRefuseDisabledAgentKindBeforeQueuing(t *testing.T) {
	roles := []authz.Role{{Name: "responder", Permissions: []authz.Permission{
		authz.IdentitiesWrite, authz.ConnectorsWrite,
	}}}
	for _, path := range []string{
		"/api/v1/connectors/targets/11111111-1111-4111-8111-111111111111/contain/preview",
		"/api/v1/identities/22222222-2222-4222-8222-222222222222/compromise/preview",
	} {
		for _, channel := range []string{"absent", "kind disabled"} {
			t.Run(path+"/"+channel, func(t *testing.T) {
				var provider func(string) bool
				if channel == "kind disabled" {
					provider = func(kind string) bool {
						if kind != "endpoint.contain" {
							t.Fatalf("checked unexpected agent kind %q", kind)
						}
						return false
					}
				}
				handler := New(nil, nil, nil, WithInsecureHeaderResolver(), WithRoles(roles...),
					WithAgentJobClaimability(provider))
				method := http.MethodGet
				body := ""
				if strings.Contains(path, "/compromise/") {
					method = http.MethodPost
					body = `{"target_id":"11111111-1111-4111-8111-111111111111"}`
				}
				request := httptest.NewRequest(method, path, strings.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("X-Tenant-ID", "33333333-3333-4333-8333-333333333333")
				request.Header.Set("X-Subject", "responder")
				request.Header.Set("X-Roles", "responder")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "endpoint.contain") {
					t.Fatalf("unclaimable review = %d %s, want 503 naming exact kind", response.Code, response.Body.String())
				}
			})
		}
	}
}
