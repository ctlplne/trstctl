package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
)

type captureApprovalRecorder struct {
	tenantID string
	resource string
	action   string
	approver string
}

func (r *captureApprovalRecorder) RecordApproval(_ context.Context, tenantID, resource, action, approver string) (int, error) {
	r.tenantID = tenantID
	r.resource = resource
	r.action = action
	r.approver = approver
	return 2, nil
}

func TestApprovalIdentityActionAcceptsRotate(t *testing.T) {
	role := authz.Role{Name: "identity-approver", Permissions: []authz.Permission{authz.CertsIssue}}
	recorder := &captureApprovalRecorder{}
	handler := New(nil, orchestrator.NewMemoryIdempotency(), nil, WithInsecureHeaderResolver(), WithRoles(role), WithApprovals(recorder))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/identities/identity-rotate-1/approvals", strings.NewReader(`{"action":"rotate"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "approve-rotate-1")
	req.Header.Set("X-Tenant-ID", "tenant-rotate")
	req.Header.Set("X-Subject", "ra-approver")
	req.Header.Set("X-Roles", "identity-approver")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("approve rotate status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if recorder.tenantID != "tenant-rotate" || recorder.resource != "identity-rotate-1" || recorder.action != "rotate" || recorder.approver != "ra-approver" {
		t.Fatalf("recorded approval = tenant:%q resource:%q action:%q approver:%q", recorder.tenantID, recorder.resource, recorder.action, recorder.approver)
	}
	var body approvalResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode approval response: %v", err)
	}
	if body.Action != "rotate" || body.Resource != "identity-rotate-1" || body.Approver != "ra-approver" || body.Approvals != 2 {
		t.Fatalf("approval response = %+v", body)
	}
}

func TestOpenAPIIdentityApprovalAdvertisesRotate(t *testing.T) {
	schemas := New(nil, nil, nil).Spec().Components.Schemas
	for _, schema := range []string{"ApprovalRequest", "Approval"} {
		action := schemas[schema].Properties["action"]
		if !stringSliceContains(action.Enum, "rotate") {
			t.Fatalf("%s.action enum = %v, want rotate", schema, action.Enum)
		}
	}
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
