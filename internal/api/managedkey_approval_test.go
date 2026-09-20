// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
)

type managedKeyApprovalServiceStub struct{}

func (managedKeyApprovalServiceStub) Generate(context.Context, string, crypto.Algorithm, string, string) (ManagedKey, error) {
	return ManagedKey{}, nil
}
func (managedKeyApprovalServiceStub) Rotate(context.Context, string, string, string, string, string) (ManagedKey, error) {
	return ManagedKey{}, nil
}
func (managedKeyApprovalServiceStub) Revoke(context.Context, string, string, string, string, string) (ManagedKey, error) {
	return ManagedKey{}, nil
}
func (managedKeyApprovalServiceStub) Zeroize(context.Context, string, string, string, string, string) (ManagedKey, error) {
	return ManagedKey{}, nil
}

func TestManagedKeyApprovalRouteCanonicalizesOpaqueKeyAction(t *testing.T) {
	recorder := &captureApprovalRecorder{}
	role := authz.Role{Name: "managed-key-approver", Permissions: []authz.Permission{authz.KeysApprove}}
	handler := New(nil, orchestrator.NewMemoryIdempotency(), nil,
		WithInsecureHeaderResolver(), WithRoles(role), WithManagedKeys(managedKeyApprovalServiceStub{}), WithApprovals(recorder))

	keyID := "https://vault.example.test/keys/root/signing/v7"
	req := httptest.NewRequest(http.MethodPost, "/api/v1/managed-keys/approvals",
		strings.NewReader(`{"key_id":"`+keyID+`","action":"zeroize","request_id":"11111111-1111-1111-1111-111111111111","intent_digest":"sha256:test"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "managed-key-approve-zeroize")
	req.Header.Set("X-Tenant-ID", "tenant-managed-key")
	req.Header.Set("X-Subject", "security-custodian")
	req.Header.Set("X-Roles", role.Name)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("approval status = %d, want 200: %s", response.Code, response.Body.String())
	}
	if recorder.tenantID != "tenant-managed-key" || recorder.command.ExpectedResourceID != keyID || recorder.command.ExpectedAction != ManagedKeyActionZeroize || recorder.command.Approver != "security-custodian" {
		t.Fatalf("recorded approval = tenant:%q command:%+v", recorder.tenantID, recorder.command)
	}
	var body managedKeyApprovalResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode managed-key approval: %v", err)
	}
	if body.Resource != keyID || body.Action != ManagedKeyActionZeroize || body.Approver != "security-custodian" || body.Approvals != 2 {
		t.Fatalf("approval response = %+v", body)
	}
}

func TestManagedKeyApprovalRouteRejectsMalformedRequestBeforeIdempotencyClaim(t *testing.T) {
	recorder := &captureApprovalRecorder{}
	role := authz.Role{Name: "managed-key-approver", Permissions: []authz.Permission{authz.KeysApprove}}
	handler := New(nil, orchestrator.NewMemoryIdempotency(), nil,
		WithInsecureHeaderResolver(), WithRoles(role), WithManagedKeys(managedKeyApprovalServiceStub{}), WithApprovals(recorder))

	request := func(requestID string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/managed-keys/approvals",
			strings.NewReader(`{"key_id":"kms/key/1","action":"rotate","request_id":"`+requestID+`","intent_digest":"sha256:test"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "managed-key-malformed-retry")
		req.Header.Set("X-Tenant-ID", "tenant-managed-key")
		req.Header.Set("X-Subject", "security-custodian")
		req.Header.Set("X-Roles", role.Name)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}

	if got := request("not-a-request-uuid"); got.Code != http.StatusNotFound || !strings.Contains(got.Body.String(), `"detail":"resource not found"`) {
		t.Fatalf("malformed managed-key approval = %d body=%s, want generic 404", got.Code, got.Body.String())
	}
	if recorder.command.RequestID != "" {
		t.Fatalf("malformed request reached approval service: %+v", recorder.command)
	}
	if got := request("11111111-1111-4111-8111-111111111111"); got.Code != http.StatusOK {
		t.Fatalf("same idempotency key after malformed refusal = %d body=%s, want 200", got.Code, got.Body.String())
	}
}

func TestManagedKeyApprovalRouteRejectsWriteOnlyAndCanonicalActionInjection(t *testing.T) {
	recorder := &captureApprovalRecorder{}
	writeOnly := authz.Role{Name: "managed-key-writer", Permissions: []authz.Permission{authz.KeysWrite}}
	approver := authz.Role{Name: "managed-key-approver", Permissions: []authz.Permission{authz.KeysApprove}}
	handler := New(nil, orchestrator.NewMemoryIdempotency(), nil,
		WithInsecureHeaderResolver(), WithRoles(writeOnly, approver), WithManagedKeys(managedKeyApprovalServiceStub{}), WithApprovals(recorder))

	request := func(role, key, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/managed-keys/approvals", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		req.Header.Set("X-Tenant-ID", "tenant-managed-key")
		req.Header.Set("X-Subject", "operator")
		req.Header.Set("X-Roles", role)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}

	if got := request(writeOnly.Name, "managed-key-write-only", `{"key_id":"kms/key/1","action":"rotate"}`); got.Code != http.StatusForbidden {
		t.Fatalf("keys:write-only approval status = %d, want 403: %s", got.Code, got.Body.String())
	}
	if got := request(approver.Name, "managed-key-prefixed-action", `{"key_id":"kms/key/1","action":"managedkey:rotate"}`); got.Code != http.StatusBadRequest {
		t.Fatalf("canonical-action injection status = %d, want 400: %s", got.Code, got.Body.String())
	}
	if recorder.command.ExpectedAction != "" {
		t.Fatalf("rejected requests reached approval recorder with action %q", recorder.command.ExpectedAction)
	}
}

func TestOpenAPIManagedKeyApprovalPinsRequestAndCanonicalResponseActions(t *testing.T) {
	schemas := New(nil, nil, nil).Spec().Components.Schemas
	requestActions := schemas["ManagedKeyApprovalRequest"].Properties["action"].Enum
	responseActions := schemas["ManagedKeyApproval"].Properties["action"].Enum
	for _, action := range managedKeyApprovalActions {
		if !stringSliceContains(requestActions, action) {
			t.Fatalf("request action enum = %v, missing %q", requestActions, action)
		}
	}
	for _, action := range managedKeyCanonicalApprovalActions {
		if !stringSliceContains(responseActions, action) {
			t.Fatalf("response action enum = %v, missing %q", responseActions, action)
		}
	}
}
