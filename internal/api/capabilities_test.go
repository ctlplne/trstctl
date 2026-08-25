// SPDX-License-Identifier: MPL-2.0

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
)

type capabilityApprovalQueue struct{}

func (capabilityApprovalQueue) ValidateApprovalRequest(context.Context, string, api.ApprovalDecisionCommand) (api.ApprovalRequestRecord, error) {
	return api.ApprovalRequestRecord{}, nil
}

func (capabilityApprovalQueue) RecordApproval(context.Context, string, api.ApprovalDecisionCommand) (api.ApprovalRequestRecord, error) {
	return api.ApprovalRequestRecord{}, nil
}

func (capabilityApprovalQueue) ListApprovalRequests(context.Context, string, api.ApprovalRequestListOptions) ([]api.ApprovalRequestRecord, error) {
	return nil, nil
}

type capabilityViewTestResponse struct {
	SchemaVersion         int `json:"schema_version"`
	ContractSchemaVersion int `json:"contract_schema_version"`
	License               struct {
		Tier  string `json:"tier"`
		State string `json:"state"`
	} `json:"license"`
	Operations []struct {
		OperationID string `json:"operation_id"`
		State       string `json:"state"`
		Code        string `json:"code"`
		Detail      string `json:"detail"`
	} `json:"operations"`
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

func TestCapabilitiesViewIncludesExactLicensedRuntimeOperations(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111111"
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithLicensedRoutes(api.LicensedRoute{
			Method:      http.MethodGet,
			Path:        "/api/v1/reconcile/agreement",
			OperationID: "getAuthorityAgreement",
			Summary:     "Report whether configured authorities agree",
			Handler: func(*api.API) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }
			},
			SuccessCode: "204",
			Permission:  authz.CertsRead,
		}),
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, capabilityViewRequest(tenantID, "viewer"))
	if response.Code != http.StatusOK {
		t.Fatalf("capabilities status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var got capabilityViewTestResponse
	if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
		t.Fatalf("decode capabilities: %v", err)
	}
	operation, ok := findRuntimeOperation(got, "getAuthorityAgreement")
	if !ok {
		t.Fatalf("runtime operations omit attached licensed route; operations=%+v", got.Operations)
	}
	if operation.State != "allowed" || operation.Code != "" || operation.Detail != "" {
		t.Fatalf("licensed runtime operation=%+v, want allowed with no refusal", operation)
	}

	coreOnly := api.New(nil, nil, nil, api.WithInsecureHeaderResolver())
	coreResponse := httptest.NewRecorder()
	coreOnly.ServeHTTP(coreResponse, capabilityViewRequest(tenantID, "viewer"))
	var core capabilityViewTestResponse
	if err := json.NewDecoder(coreResponse.Body).Decode(&core); err != nil {
		t.Fatalf("decode core capabilities: %v", err)
	}
	if _, ok := findRuntimeOperation(core, "getAuthorityAgreement"); ok {
		t.Fatalf("core-only runtime falsely advertised unattached licensed operation")
	}
}

func findRuntimeOperation(view capabilityViewTestResponse, operationID string) (struct {
	OperationID string `json:"operation_id"`
	State       string `json:"state"`
	Code        string `json:"code"`
	Detail      string `json:"detail"`
}, bool) {
	for _, operation := range view.Operations {
		if operation.OperationID == operationID {
			return operation, true
		}
	}
	return struct {
		OperationID string `json:"operation_id"`
		State       string `json:"state"`
		Code        string `json:"code"`
		Detail      string `json:"detail"`
	}{}, false
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
	if viewer.SchemaVersion != 2 || viewer.ContractSchemaVersion != 3 || len(viewer.Items) != 79 {
		t.Fatalf("viewer schema/contract/items=%d/%d/%d, want 2/3/79", viewer.SchemaVersion, viewer.ContractSchemaVersion, len(viewer.Items))
	}
	if len(viewer.Operations) == 0 {
		t.Fatal("viewer runtime operation registry is empty")
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
	for _, item := range operator.Items {
		for _, action := range item.Actions.Unavailable {
			if strings.TrimSpace(action.Detail) == "" {
				t.Errorf("capability %s operation %s has an empty unavailable reason", item.CapabilityID, action.OperationID)
			}
		}
	}
	f2 = findCapabilityViewItem(t, operator, "F2")
	if f2.AuthorizationState != "full" || len(f2.Actions.Denied) != 0 {
		t.Fatalf("operator F2 auth=%q denied=%v, want full/none", f2.AuthorizationState, f2.Actions.Denied)
	}
	f64 := findCapabilityViewItem(t, operator, "F64")
	if f64.RuntimeState != "unavailable" {
		t.Fatalf("operator F64 runtime=%q, want unavailable without the native secret store", f64.RuntimeState)
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
	f63 := findCapabilityViewItem(t, operator, "F63")
	if f63.RuntimeState != "unavailable" || len(f63.Actions.Allowed) != 0 {
		t.Fatalf("operator F63 runtime=%q allowed=%v, want unavailable/none without the native secret store", f63.RuntimeState, f63.Actions.Allowed)
	}
	for _, operationID := range []string{"createSecret", "listSecrets", "getSecret", "getSecretVersion", "recoverSecretAt", "rotateSecret", "deleteSecret"} {
		action := findUnavailableCapabilityAction(t, f63, operationID)
		if action.Code != "dependency_not_configured" || !strings.Contains(action.Detail, "native secret store is turned off") {
			t.Fatalf("F63 %s unavailable=%+v, want exact native-store dependency reason", operationID, action)
		}
	}
	// F68 intentionally mixes independent posture/configuration reads with the
	// native-store-backed sync execution. Turning the store off must not erase
	// the useful read-only surfaces.
	f68 := findCapabilityViewItem(t, operator, "F68")
	if f68.RuntimeState != "partially_available" || !containsCapabilityString(f68.Actions.Allowed, "listSecretSyncTargets") {
		t.Fatalf("operator F68 runtime=%q allowed=%v, want independent sync target posture", f68.RuntimeState, f68.Actions.Allowed)
	}
	if action := findUnavailableCapabilityAction(t, f68, "syncSecret"); action.Code != "dependency_not_configured" {
		t.Fatalf("F68 syncSecret unavailable=%+v, want dependency_not_configured", action)
	}
	f66 := findCapabilityViewItem(t, operator, "F66")
	if f66.RuntimeState != "unavailable" {
		t.Fatalf("operator F66 runtime=%q, want unavailable without Transit service", f66.RuntimeState)
	}
	f33 := findCapabilityViewItem(t, operator, "F33")
	for _, operationID := range []string{"listApprovalRequests", "approveApprovalRequest", "denyApprovalRequest"} {
		action := findUnavailableCapabilityAction(t, f33, operationID)
		if action.Code != "dependency_not_configured" || !strings.Contains(action.Detail, "dual-control approval") {
			t.Fatalf("F33 %s unavailable=%+v, want exact approval dependency reason", operationID, action)
		}
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

func TestCapabilitiesViewPromotesApprovalQueueOnlyWhenConfigured(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111111"
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithApprovals(capabilityApprovalQueue{}),
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, capabilityViewRequest(tenantID, "operator"))
	if response.Code != http.StatusOK {
		t.Fatalf("configured capability status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var view capabilityViewTestResponse
	if err := json.NewDecoder(response.Body).Decode(&view); err != nil {
		t.Fatalf("decode configured capability response: %v", err)
	}
	f33 := findCapabilityViewItem(t, view, "F33")
	for _, operationID := range []string{"listApprovalRequests", "approveApprovalRequest", "denyApprovalRequest"} {
		if !containsCapabilityString(f33.Actions.Allowed, operationID) {
			t.Errorf("configured F33 allowed=%v, want %s", f33.Actions.Allowed, operationID)
		}
	}
}

func TestCapabilitiesViewPromotesNativeSecretStoreOnlyWhenConfigured(t *testing.T) {
	const tenantID = "11111111-1111-4111-8111-111111111111"
	handler := api.New(nil, nil, nil,
		api.WithInsecureHeaderResolver(),
		api.WithSecrets(api.SecretsBackend{}),
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, capabilityViewRequest(tenantID, "operator"))
	if response.Code != http.StatusOK {
		t.Fatalf("configured capability status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var view capabilityViewTestResponse
	if err := json.NewDecoder(response.Body).Decode(&view); err != nil {
		t.Fatalf("decode configured capability response: %v", err)
	}
	f63 := findCapabilityViewItem(t, view, "F63")
	if f63.RuntimeState != "available" || len(f63.Actions.Unavailable) != 0 {
		t.Fatalf("configured F63 runtime=%q unavailable=%+v, want available/none", f63.RuntimeState, f63.Actions.Unavailable)
	}
	for _, operationID := range []string{"createSecret", "listSecrets", "getSecret", "getSecretVersion", "recoverSecretAt", "rotateSecret", "deleteSecret"} {
		if !containsCapabilityString(f63.Actions.Allowed, operationID) {
			t.Errorf("configured F63 allowed=%v, want %s", f63.Actions.Allowed, operationID)
		}
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

func findUnavailableCapabilityAction(t *testing.T, item struct {
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
}, operationID string) struct {
	OperationID string `json:"operation_id"`
	Code        string `json:"code"`
	Detail      string `json:"detail"`
} {
	t.Helper()
	for _, action := range item.Actions.Unavailable {
		if action.OperationID == operationID {
			return action
		}
	}
	t.Fatalf("capability %s unavailable=%+v, want operation %s", item.CapabilityID, item.Actions.Unavailable, operationID)
	return item.Actions.Unavailable[0]
}
