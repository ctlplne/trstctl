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
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/policy"
	"trstctl.com/trstctl/internal/store"
)

type approvalQueueRecorder struct {
	records  []ApprovalRequestRecord
	commands []ApprovalDecisionCommand
	queries  []ApprovalRequestListOptions
}

type approvalQueueABAC struct {
	calls       []string
	denyReasons map[string]string
}

func (a *approvalQueueABAC) EvaluateDeny(_ context.Context, input policy.ABACInput) (policy.ABACDecision, error) {
	a.calls = append(a.calls, input.Permission)
	reason, denied := a.denyReasons[input.Permission]
	return policy.ABACDecision{Deny: denied, Reason: reason}, nil
}

func (r *approvalQueueRecorder) ValidateApprovalRequest(_ context.Context, _ string, command ApprovalDecisionCommand) (ApprovalRequestRecord, error) {
	for _, record := range r.records {
		if record.ID != command.RequestID {
			continue
		}
		if record.IntentDigest != command.IntentDigest ||
			command.ExpectedResourceKind != "" && command.ExpectedResourceKind != record.ResourceKind ||
			command.ExpectedResourceID != "" && command.ExpectedResourceID != record.ResourceID ||
			command.ExpectedAction != "" && command.ExpectedAction != record.Action {
			return ApprovalRequestRecord{}, store.ErrApprovalDigestMismatch
		}
		return record, nil
	}
	return ApprovalRequestRecord{}, store.ErrApprovalRequestNotFound
}

func (r *approvalQueueRecorder) RecordApproval(_ context.Context, _ string, command ApprovalDecisionCommand) (ApprovalRequestRecord, error) {
	record, err := r.ValidateApprovalRequest(context.Background(), "", command)
	if err != nil {
		return ApprovalRequestRecord{}, err
	}
	r.commands = append(r.commands, command)
	record.ApprovalCount++
	if command.Decision == store.ApprovalDecisionDeny {
		record.Status = store.ApprovalStatusDenied
	} else if record.ApprovalCount >= record.RequiredApprovals {
		record.Status = store.ApprovalStatusApproved
	}
	return record, nil
}

func (r *approvalQueueRecorder) ListApprovalRequests(_ context.Context, _ string, options ApprovalRequestListOptions) ([]ApprovalRequestRecord, error) {
	r.queries = append(r.queries, options)
	return append([]ApprovalRequestRecord(nil), r.records...), nil
}

func TestApprovalQueueFiltersEachDomainByItsRealReviewPermission(t *testing.T) {
	records := approvalAuthorizationFixtures()
	for _, tc := range []struct {
		name     string
		perm     authz.Permission
		wantIDs  []string
		wantCert bool
		wantSec  bool
		wantKey  bool
	}{
		{name: "certificate reviewer", perm: authz.CertsIssue,
			wantIDs: []string{records[0].ID, records[1].ID, records[2].ID}, wantCert: true},
		{name: "secret reviewer", perm: authz.SecretsWrite,
			wantIDs: []string{records[3].ID}, wantSec: true},
		{name: "managed key reviewer", perm: authz.KeysApprove,
			wantIDs: []string{records[4].ID}, wantKey: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := &approvalQueueRecorder{records: records}
			role := authz.Role{Name: "reviewer", Permissions: []authz.Permission{tc.perm}}
			handler := New(nil, orchestrator.NewMemoryIdempotency(), nil,
				WithInsecureHeaderResolver(), WithRoles(role), WithApprovals(recorder))
			req := approvalQueueRequest(http.MethodGet, "/api/v1/approval-requests?status=pending", "reviewer", "reviewer-1", "")
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("list status = %d, want 200: %s", rr.Code, rr.Body.String())
			}
			var response approvalRequestList
			if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			gotIDs := make([]string, 0, len(response.Items))
			for _, record := range response.Items {
				gotIDs = append(gotIDs, record.ID)
			}
			if strings.Join(gotIDs, ",") != strings.Join(tc.wantIDs, ",") {
				t.Fatalf("visible approval IDs = %v, want %v", gotIDs, tc.wantIDs)
			}
			if len(recorder.queries) != 1 {
				t.Fatalf("list calls = %d, want 1", len(recorder.queries))
			}
			query := recorder.queries[0]
			if query.CertificateOperations != tc.wantCert || query.SecretOperations != tc.wantSec || query.ManagedKeyOperations != tc.wantKey {
				t.Fatalf("domain visibility = %+v, want cert=%v secret=%v key=%v", query, tc.wantCert, tc.wantSec, tc.wantKey)
			}
		})
	}
}

func TestApprovalQueueSyntheticReviewPermissionIsRouteAdmissionOnly(t *testing.T) {
	records := approvalAuthorizationFixtures()
	recorder := &approvalQueueRecorder{records: records}
	overlay := &approvalQueueABAC{denyReasons: map[string]string{
		string(authz.ApprovalsReview): "synthetic permissions are denied",
	}}
	role := authz.Role{Name: "certificate-reviewer", Permissions: []authz.Permission{authz.CertsIssue}}
	handler := New(nil, orchestrator.NewMemoryIdempotency(), nil,
		WithInsecureHeaderResolver(), WithRoles(role), WithApprovals(recorder),
		WithABACDenyOverlay(overlay, nil, nil))
	req := approvalQueueRequest(http.MethodGet, "/api/v1/approval-requests?status=pending",
		"certificate-reviewer", "cert-reviewer", "")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("synthetic-permission-denying overlay blocked genuine certificate reviewer = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	for _, permission := range overlay.calls {
		if permission == string(authz.ApprovalsReview) {
			t.Fatalf("synthetic route-admission permission reached ABAC: calls=%v", overlay.calls)
		}
		if permission != string(authz.CertsIssue) {
			t.Fatalf("ABAC evaluated non-certificate permission %q for certificate-only reviewer: calls=%v", permission, overlay.calls)
		}
	}
	if len(overlay.calls) == 0 {
		t.Fatal("exact certificate-domain ABAC was not evaluated")
	}
}

func TestApprovalQueueRealDomainABACDenyStillFiltersAndRejects(t *testing.T) {
	records := approvalAuthorizationFixtures()
	recorder := &approvalQueueRecorder{records: records}
	overlay := &approvalQueueABAC{denyReasons: map[string]string{
		string(authz.SecretsWrite): "secret reviews require an active change window",
	}}
	role := authz.Role{Name: "certificate-secret-reviewer", Permissions: []authz.Permission{authz.CertsIssue, authz.SecretsWrite}}
	handler := New(nil, orchestrator.NewMemoryIdempotency(), nil,
		WithInsecureHeaderResolver(), WithRoles(role), WithApprovals(recorder),
		WithABACDenyOverlay(overlay, nil, nil))

	listReq := approvalQueueRequest(http.MethodGet, "/api/v1/approval-requests?status=pending",
		"certificate-secret-reviewer", "reviewer-1", "")
	listRR := httptest.NewRecorder()
	handler.ServeHTTP(listRR, listReq)
	if listRR.Code != http.StatusOK {
		t.Fatalf("mixed-domain list status = %d, want 200: %s", listRR.Code, listRR.Body.String())
	}
	var list approvalRequestList
	if err := json.Unmarshal(listRR.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	for _, record := range list.Items {
		if record.ResourceKind == "secret" {
			t.Fatalf("real-domain ABAC-denied secret leaked through list: %+v", record)
		}
	}

	secret := records[3]
	body := `{"intent_digest":"` + secret.IntentDigest + `"}`
	decisionReq := approvalQueueRequest(http.MethodPost, "/api/v1/approval-requests/"+secret.ID+"/approvals",
		"certificate-secret-reviewer", "reviewer-1", body)
	decisionRR := httptest.NewRecorder()
	handler.ServeHTTP(decisionRR, decisionReq)
	if decisionRR.Code != http.StatusForbidden {
		t.Fatalf("real-domain ABAC-denied secret approval = %d, want 403: %s", decisionRR.Code, decisionRR.Body.String())
	}
	if len(recorder.commands) != 0 {
		t.Fatalf("real-domain ABAC denial recorded decisions: %+v", recorder.commands)
	}
}

func TestGenericApprovalDecisionCannotCrossDomainPermission(t *testing.T) {
	records := approvalAuthorizationFixtures()
	secret := records[3]
	recorder := &approvalQueueRecorder{records: records}
	role := authz.Role{Name: "certificate-reviewer", Permissions: []authz.Permission{authz.CertsIssue}}
	handler := New(nil, orchestrator.NewMemoryIdempotency(), nil,
		WithInsecureHeaderResolver(), WithRoles(role), WithApprovals(recorder))
	body := `{"intent_digest":"` + secret.IntentDigest + `"}`
	req := approvalQueueRequest(http.MethodPost, "/api/v1/approval-requests/"+secret.ID+"/approvals",
		"certificate-reviewer", "cert-reviewer", body)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("certificate-only reviewer approved secret = %d, want 403: %s", rr.Code, rr.Body.String())
	}
	if len(recorder.commands) != 0 {
		t.Fatalf("unauthorized secret approval recorded commands: %+v", recorder.commands)
	}
}

func TestGenericApprovalDenialRecordsImmutableReasonInsteadOfMutatingTarget(t *testing.T) {
	records := approvalAuthorizationFixtures()
	secret := records[3]
	recorder := &approvalQueueRecorder{records: records}
	role := authz.Role{Name: "secret-reviewer", Permissions: []authz.Permission{authz.SecretsWrite}}
	handler := New(nil, orchestrator.NewMemoryIdempotency(), nil,
		WithInsecureHeaderResolver(), WithRoles(role), WithApprovals(recorder))
	body := `{"intent_digest":"` + secret.IntentDigest + `","reason":"unsafe rollout window"}`
	req := approvalQueueRequest(http.MethodPost, "/api/v1/approval-requests/"+secret.ID+"/denials",
		"secret-reviewer", "secret-reviewer-1", body)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("deny status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if len(recorder.commands) != 1 {
		t.Fatalf("recorded decisions = %d, want 1", len(recorder.commands))
	}
	decision := recorder.commands[0]
	if decision.RequestID != secret.ID || decision.IntentDigest != secret.IntentDigest ||
		decision.Decision != store.ApprovalDecisionDeny || decision.Reason != "unsafe rollout window" ||
		decision.Approver != "secret-reviewer-1" {
		t.Fatalf("denial command = %+v", decision)
	}
	var response approvalResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Status != store.ApprovalStatusDenied {
		t.Fatalf("denial response status = %q, want denied", response.Status)
	}
}

func TestGenericApprovalDenialRequiresReason(t *testing.T) {
	records := approvalAuthorizationFixtures()
	identity := records[0]
	recorder := &approvalQueueRecorder{records: records}
	role := authz.Role{Name: "certificate-reviewer", Permissions: []authz.Permission{authz.CertsIssue}}
	handler := New(nil, orchestrator.NewMemoryIdempotency(), nil,
		WithInsecureHeaderResolver(), WithRoles(role), WithApprovals(recorder))
	body := `{"intent_digest":"` + identity.IntentDigest + `","reason":"  "}`
	req := approvalQueueRequest(http.MethodPost, "/api/v1/approval-requests/"+identity.ID+"/denials",
		"certificate-reviewer", "cert-reviewer", body)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty denial reason status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if len(recorder.commands) != 0 {
		t.Fatalf("empty reason recorded commands: %+v", recorder.commands)
	}
}

func approvalQueueRequest(method, target, role, subject, body string) *http.Request {
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, target, reader)
	req.Header.Set("X-Tenant-ID", "tenant-approval")
	req.Header.Set("X-Subject", subject)
	req.Header.Set("X-Roles", role)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		req.Header.Set("Idempotency-Key", "approval-test-"+subject)
	}
	return req
}

func approvalAuthorizationFixtures() []ApprovalRequestRecord {
	base := []ApprovalRequestRecord{
		{ID: "77000000-0000-4000-8000-000000000301", ResourceKind: "identity", Action: "issue"},
		{ID: "77000000-0000-4000-8000-000000000302", ResourceKind: "ephemeral", Action: "issue"},
		{ID: "77000000-0000-4000-8000-000000000303", ResourceKind: "code_signing", Action: "sign"},
		{ID: "77000000-0000-4000-8000-000000000304", ResourceKind: "secret", Action: "rotate"},
		{ID: "77000000-0000-4000-8000-000000000305", ResourceKind: "managed_key", Action: "managedkey:zeroize"},
		// Unknown kind/action pairs are intentionally never reviewable through the
		// generic queue until their domain permission is explicitly mapped.
		{ID: "77000000-0000-4000-8000-000000000306", ResourceKind: "secret", Action: "sign"},
	}
	for i := range base {
		base[i].IntentDigest = "sha256:" + base[i].ID
		base[i].ResourceID = base[i].ResourceKind + ":target"
		base[i].Requester = "requester-1"
		base[i].RequiredApprovals = 2
		base[i].Status = store.ApprovalStatusPending
		base[i].CreatedAt = "2026-08-10T12:00:00Z"
		base[i].ExpiresAt = "2026-08-10T13:00:00Z"
	}
	return base
}

var _ ApprovalRecorder = (*approvalQueueRecorder)(nil)
var _ ApprovalRequestLister = (*approvalQueueRecorder)(nil)
