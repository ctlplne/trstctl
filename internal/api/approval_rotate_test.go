// SPDX-License-Identifier: MPL-2.0

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
	command  ApprovalDecisionCommand
}

func (r *captureApprovalRecorder) ValidateApprovalRequest(_ context.Context, tenantID string, command ApprovalDecisionCommand) (ApprovalRequestRecord, error) {
	r.tenantID = tenantID
	r.command = command
	return ApprovalRequestRecord{
		ID: command.RequestID, IntentDigest: command.IntentDigest,
		ResourceID: command.ExpectedResourceID, ResourceKind: command.ExpectedResourceKind,
		Action: command.ExpectedAction, RequiredApprovals: 2, Status: "pending",
	}, nil
}

func (r *captureApprovalRecorder) RecordApproval(_ context.Context, tenantID string, command ApprovalDecisionCommand) (ApprovalRequestRecord, error) {
	r.tenantID = tenantID
	r.command = command
	return ApprovalRequestRecord{
		ID: command.RequestID, IntentDigest: command.IntentDigest,
		ResourceID: command.ExpectedResourceID, ResourceKind: command.ExpectedResourceKind,
		Action: command.ExpectedAction, ApprovalCount: 2, RequiredApprovals: 2,
		Status: "approved",
	}, nil
}

func TestApprovalIdentityActionAcceptsRotate(t *testing.T) {
	role := authz.Role{Name: "identity-approver", Permissions: []authz.Permission{authz.CertsIssue}}
	recorder := &captureApprovalRecorder{}
	handler := New(nil, orchestrator.NewMemoryIdempotency(), nil, WithInsecureHeaderResolver(), WithRoles(role), WithApprovals(recorder))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/identities/identity-rotate-1/approvals", strings.NewReader(`{"action":"rotate","request_id":"11111111-1111-1111-1111-111111111111","intent_digest":"sha256:test"}`))
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
	if recorder.tenantID != "tenant-rotate" || recorder.command.ExpectedResourceID != "identity-rotate-1" || recorder.command.ExpectedAction != "rotate" || recorder.command.Approver != "ra-approver" {
		t.Fatalf("recorded approval = tenant:%q command:%+v", recorder.tenantID, recorder.command)
	}
	var body approvalResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode approval response: %v", err)
	}
	if body.Action != "rotate" || body.Resource != "identity-rotate-1" || body.Approver != "ra-approver" || body.Approvals != 2 {
		t.Fatalf("approval response = %+v", body)
	}
}

func TestOpenAPIIdentityApprovalAdvertisesRotateAndCodeSign(t *testing.T) {
	schemas := New(nil, nil, nil).Spec().Components.Schemas
	for _, schema := range []string{"ApprovalRequest", "Approval"} {
		action := schemas[schema].Properties["action"]
		if !stringSliceContains(action.Enum, "rotate") {
			t.Fatalf("%s.action enum = %v, want rotate", schema, action.Enum)
		}
		if !stringSliceContains(action.Enum, "sign") {
			t.Fatalf("%s.action enum = %v, want sign", schema, action.Enum)
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
