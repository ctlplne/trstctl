// SPDX-License-Identifier: MPL-2.0

package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
)

type capabilityViewTestResponse struct {
	SchemaVersion         int `json:"schema_version"`
	ContractSchemaVersion int `json:"contract_schema_version"`
	License               struct {
		Tier  string `json:"tier"`
		State string `json:"state"`
	} `json:"license"`
	Items []struct {
		CapabilityID       string `json:"capability_id"`
		Name               string `json:"name"`
		RuntimeState       string `json:"runtime_state"`
		AuthorizationState string `json:"authorization_state"`
		Actions            struct {
			Allowed     []string `json:"allowed"`
			Scoped      []string `json:"scoped"`
			Denied      []string `json:"denied"`
			Unavailable []struct {
				OperationID string `json:"operation_id"`
				Code        string `json:"code"`
				Detail      string `json:"detail"`
			} `json:"unavailable"`
		} `json:"actions"`
	} `json:"items"`
}

func TestCapabilitiesViewIsAuthenticatedSanitizedAndAuthorizationAware(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111111"
	capabilityOnly := authz.Role{Name: "capability-only", Permissions: []authz.Permission{authz.CapabilitiesRead}}
	handler := api.New(nil, nil, nil, api.WithInsecureHeaderResolver(), api.WithRoles(capabilityOnly))

	unauthenticated := httptest.NewRecorder()
	handler.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d body=%s, want 401", unauthenticated.Code, unauthenticated.Body.String())
	}

	agent := capabilityViewRequest(tenantID, "agent")
	agentResponse := httptest.NewRecorder()
	handler.ServeHTTP(agentResponse, agent)
	if agentResponse.Code != http.StatusForbidden {
		t.Fatalf("agent status=%d body=%s, want 403", agentResponse.Code, agentResponse.Body.String())
	}

	viewerResponse := httptest.NewRecorder()
	handler.ServeHTTP(viewerResponse, capabilityViewRequest(tenantID, "viewer"))
	if viewerResponse.Code != http.StatusOK {
		t.Fatalf("viewer status=%d body=%s, want 200", viewerResponse.Code, viewerResponse.Body.String())
	}
	viewerBody := viewerResponse.Body.String()
	for _, forbidden := range []string{"candidate_sha", "permission_authority", "secret_data_handling", "source_backend", "source_frontend", "73b871089f46e4cc9e95ca10473b9ae5872a53cd", "web/src/", "internal/"} {
		if strings.Contains(viewerBody, forbidden) {
			t.Fatalf("capability response leaked %q: %.800s", forbidden, viewerBody)
		}
	}
	var viewer capabilityViewTestResponse
	if err := json.Unmarshal([]byte(viewerBody), &viewer); err != nil {
		t.Fatalf("decode viewer response: %v", err)
	}
	if viewer.SchemaVersion != 1 || viewer.ContractSchemaVersion != 3 || len(viewer.Items) != 79 {
		t.Fatalf("viewer schema/contract/items=%d/%d/%d, want 1/3/79", viewer.SchemaVersion, viewer.ContractSchemaVersion, len(viewer.Items))
	}
	if viewer.License.Tier != "community" || viewer.License.State != "community" {
		t.Fatalf("community license posture=%+v", viewer.License)
	}
	f2 := findCapabilityViewItem(t, viewer, "F2")
	if f2.RuntimeState != "available" || f2.AuthorizationState != "partial" {
		t.Fatalf("viewer F2 runtime/auth=%q/%q, want available/partial", f2.RuntimeState, f2.AuthorizationState)
	}
	if !containsCapabilityString(f2.Actions.Allowed, "listDiscoverySources") || !containsCapabilityString(f2.Actions.Denied, "createDiscoverySource") {
		t.Fatalf("viewer F2 actions allowed=%v denied=%v", f2.Actions.Allowed, f2.Actions.Denied)
	}

	operatorResponse := httptest.NewRecorder()
	handler.ServeHTTP(operatorResponse, capabilityViewRequest(tenantID, "operator"))
	if operatorResponse.Code != http.StatusOK {
		t.Fatalf("operator status=%d body=%s, want 200", operatorResponse.Code, operatorResponse.Body.String())
	}
	var operator capabilityViewTestResponse
	if err := json.NewDecoder(operatorResponse.Body).Decode(&operator); err != nil {
		t.Fatalf("decode operator response: %v", err)
	}
	f2 = findCapabilityViewItem(t, operator, "F2")
	if f2.AuthorizationState != "full" || len(f2.Actions.Denied) != 0 {
		t.Fatalf("operator F2 auth=%q denied=%v, want full/none", f2.AuthorizationState, f2.Actions.Denied)
	}
	f64 := findCapabilityViewItem(t, operator, "F64")
	if f64.RuntimeState != "partially_available" {
		t.Fatalf("operator F64 runtime=%q, want partially_available", f64.RuntimeState)
	}
	foundUnavailable := false
	for _, action := range f64.Actions.Unavailable {
		if action.OperationID == "importSecrets" && action.Code == "not_implemented" && action.Detail != "" {
			foundUnavailable = true
		}
	}
	if !foundUnavailable {
		t.Fatalf("F64 unavailable actions=%+v, want honest importSecrets refusal", f64.Actions.Unavailable)
	}

	capabilityOnlyResponse := httptest.NewRecorder()
	handler.ServeHTTP(capabilityOnlyResponse, capabilityViewRequest(tenantID, capabilityOnly.Name))
	if capabilityOnlyResponse.Code != http.StatusOK {
		t.Fatalf("capability-only status=%d body=%s, want 200", capabilityOnlyResponse.Code, capabilityOnlyResponse.Body.String())
	}
	var restricted capabilityViewTestResponse
	if err := json.NewDecoder(capabilityOnlyResponse.Body).Decode(&restricted); err != nil {
		t.Fatalf("decode capability-only response: %v", err)
	}
	f2 = findCapabilityViewItem(t, restricted, "F2")
	if f2.AuthorizationState != "none" || len(f2.Actions.Allowed) != 0 {
		t.Fatalf("capability-only F2 auth=%q allowed=%v, want none/none", f2.AuthorizationState, f2.Actions.Allowed)
	}
}

func TestCapabilitiesViewOpenAPIContractIsGeneratedAndSecured(t *testing.T) {
	raw, err := json.Marshal(api.New(nil, nil, nil).Spec())
	if err != nil {
		t.Fatalf("marshal OpenAPI document: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode OpenAPI document: %v", err)
	}
	paths := doc["paths"].(map[string]any)
	operation := paths["/api/v1/capabilities"].(map[string]any)["get"].(map[string]any)
	if operation["operationId"] != "listCapabilities" {
		t.Fatalf("capability operationId=%v, want listCapabilities", operation["operationId"])
	}
	if operation["x-trstctl-permission"] != string(authz.CapabilitiesRead) || !hasBearerSecurity(operation) {
		t.Fatalf("capability security=%v permission=%v", operation["security"], operation["x-trstctl-permission"])
	}
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	for _, name := range []string{"CapabilityView", "CapabilityViewItem", "CapabilityViewStage", "CapabilityViewActions", "CapabilityUnavailableAction", "CapabilityLicensePosture"} {
		if schemas[name] == nil {
			t.Errorf("OpenAPI component %s is missing", name)
		}
	}
}

func capabilityViewRequest(tenantID, role string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil)
	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set("X-Subject", "capability-reader")
	req.Header.Set("X-Roles", role)
	return req
}

func findCapabilityViewItem(t *testing.T, response capabilityViewTestResponse, id string) struct {
	CapabilityID       string `json:"capability_id"`
	Name               string `json:"name"`
	RuntimeState       string `json:"runtime_state"`
	AuthorizationState string `json:"authorization_state"`
	Actions            struct {
		Allowed     []string `json:"allowed"`
		Scoped      []string `json:"scoped"`
		Denied      []string `json:"denied"`
		Unavailable []struct {
			OperationID string `json:"operation_id"`
			Code        string `json:"code"`
			Detail      string `json:"detail"`
		} `json:"unavailable"`
	} `json:"actions"`
} {
	t.Helper()
	for _, item := range response.Items {
		if item.CapabilityID == id {
			return item
		}
	}
	t.Fatalf("capability %s is missing", id)
	return response.Items[0]
}

func containsCapabilityString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
