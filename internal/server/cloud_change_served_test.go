// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"
	cloudchange "trstctl.com/trstctl/internal/cloudentitlements/change"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/cloudentitlements/assessment"
	"trstctl.com/trstctl/internal/cloudentitlements/awsiam"
	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/projections"
)

func TestServedApprovedCloudKeyRevocationA264(t *testing.T) {
	endpoint := os.Getenv("TRSTCTL_A264_IAM_ENDPOINT")
	path := os.Getenv("TRSTCTL_A264_IAM_SESSION_FILE")
	if endpoint == "" || path == "" {
		t.Skip("owned IAM endpoint/session file and a264-change552 user/key fixture required")
	}
	t.Setenv("TRSTCTL_A264_CHANGE_READER_PATH", path)
	t.Setenv("TRSTCTL_A264_CHANGE_WRITER_PATH", path)
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs("env:TRSTCTL_A264_CHANGE_READER_PATH", "env:TRSTCTL_A264_CHANGE_WRITER_PATH"))
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "cloud-operator", "access:write", "access:read", "discovery:read", "discovery:write", "approvals:review", "access:approve", string(authz.PrivateEgress))
	reviewer := seedScopedTokenSubject(t, h.store, h.tenant, "cloud-reviewer", "approvals:review", "access:approve", "access:read", "access:write", string(authz.PrivateEgress))
	arn := "arn:aws:iam::000000000000:user/a264-change552"
	now := time.Now().UTC()
	cfg := assessment.SourceConfig{Endpoint: endpoint, SessionFileRef: "env:TRSTCTL_A264_CHANGE_READER_PATH", AllowPrivateEndpoint: true, PrivateEgressCIDRs: []string{serviceNowSinkCIDR(t, endpoint)}, Principals: []awsiam.Selection{{Kind: awspolicy.IAMUser, Name: "a264-change552"}}, Input: assessment.Input{Checks: []assessment.Check{{PrincipalARN: arn, Action: "s3:GetObject", Resource: "arn:aws:s3:::a264-workload/note", ResourceAccountID: "000000000000", Context: awspolicy.Context{Complete: true, Values: map[string][]string{"aws:RequestedRegion": {"us-east-1"}}}}}, Supplemental: []assessment.Supplemental{{PrincipalARN: arn, SourceRef: "recorded:owned-organization-fixture", Resource: "arn:aws:s3:::a264-workload/note", ResourceAccountID: "000000000000", ResourcePolicies: assessment.PolicySet{Coverage: awspolicy.Absent}, SCPCoverage: awspolicy.Absent, RCPCoverage: awspolicy.Absent}}, Activity: assessment.ActivityEvidence{SourceRef: "recorded:owned-activity-window", Start: now.Add(-30 * 24 * time.Hour), End: now, Scopes: []assessment.ActivityScope{{PrincipalARN: arn, Action: "s3:GetObject", Resource: "arn:aws:s3:::a264-workload/note", Complete: true}}}}}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", operator, "a264-change-source", map[string]any{"kind": assessment.SourceKind, "name": "owned IAM change source", "config": cfg})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil {
		t.Fatalf("change source: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/runs", operator, "a264-change-capture", map[string]any{"source_id": source.ID})
	var run struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &run) != nil {
		t.Fatalf("change capture queue: %d %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+run.ID, operator, nil)
	var findings struct {
		Items []struct {
			ID       string          `json:"id"`
			Metadata json.RawMessage `json:"metadata"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &findings) != nil || len(findings.Items) != 1 {
		t.Fatalf("captured IAM change finding: %d %s", status, body)
	}
	value, err := assessment.DecodeAssessment(findings.Items[0].Metadata)
	if err != nil || len(value.Keys) != 1 {
		t.Fatalf("owned fixture needs one key: %v keys=%d", err, len(value.Keys))
	}
	keyID := value.Keys[0].Key.ID
	request := map[string]any{"finding_id": findings.Items[0].ID, "action": "revoke_key", "access_key_id": keyID, "writer_session_file_ref": "env:TRSTCTL_A264_CHANGE_WRITER_PATH", "reason": "Retire the exact unused fixture key after human review", "required_approvals": 1}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/cloud-entitlements/changes", operator, "a264-key-revoke-proposal", request)
	var change struct {
		ID                string `json:"id"`
		State             string `json:"state"`
		ApprovalRequestID string `json:"approval_request_id"`
		IntentDigest      string `json:"intent_digest"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &change) != nil || change.ID == "" || change.State != "awaiting_approval" || change.ApprovalRequestID == "" || change.IntentDigest == "" {
		t.Fatalf("exact approved key proposal: %d %s", status, body)
	}
	replayStatus, replayBody := secretsReqKey(t, h, http.MethodPost, "/api/v1/cloud-entitlements/changes", operator, "a264-key-revoke-proposal", request)
	if replayStatus != status || string(replayBody) != string(body) {
		t.Fatal("proposal retry created a different cloud change")
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/cloud-entitlements/changes/"+change.ID+"/execute", operator, "a264-before-review", nil)
	if status != http.StatusPreconditionRequired {
		t.Fatalf("unapproved cloud effect accepted: %d %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/approval-requests", reviewer, nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(change.ApprovalRequestID)) || !bytes.Contains(body, []byte(`"resource_kind":"cloud_machine"`)) {
		t.Fatalf("review queue omitted exact cloud capability: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/cloud-entitlements/changes/"+change.ID+"/execute", reviewer, "a264-wrong-executor", nil)
	if status != http.StatusForbidden {
		t.Fatalf("non-requester executed a cloud change: %d %s", status, body)
	}
	approval := map[string]any{"intent_digest": change.IntentDigest}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/approval-requests/"+change.ApprovalRequestID+"/approvals", operator, "a264-self-review", approval)
	if status != http.StatusForbidden {
		t.Fatalf("requester self approved cloud revoke: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/approval-requests/"+change.ApprovalRequestID+"/approvals", reviewer, "a264-distinct-review", approval)
	if status != http.StatusOK {
		t.Fatalf("distinct cloud approval: %d %s", status, body)
	}
	// Inject a database rollback after the queue event is durable. No native
	// effect may happen before approval consumption and outbox intent commit.
	if _, err := h.store.SystemPool().Exec(t.Context(), `CREATE FUNCTION cloud_change_queue_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.state='queued' THEN RAISE EXCEPTION 'owned cloud queue rollback'; END IF; RETURN NEW; END $$; CREATE TRIGGER cloud_change_queue_fault BEFORE UPDATE ON cloud_machine_changes FOR EACH ROW EXECUTE FUNCTION cloud_change_queue_fault()`); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/cloud-entitlements/changes/"+change.ID+"/execute", operator, "a264-lost-queue-commit", nil)
	if status < 400 {
		t.Fatalf("queue fault not exercised: %d %s", status, body)
	}
	plan, err := h.store.GetCloudMachineChange(t.Context(), h.tenant, change.ID)
	if err != nil || plan.State != "awaiting_approval" {
		t.Fatalf("partial queued state committed: %+v %v", plan, err)
	}
	if _, err := h.store.SystemPool().Exec(t.Context(), `DROP TRIGGER cloud_change_queue_fault ON cloud_machine_changes; DROP FUNCTION cloud_change_queue_fault()`); err != nil {
		t.Fatal(err)
	}
	if healed, err := h.srv.orch.ReconcileCloudMachineChanges(t.Context()); err != nil || healed != 1 {
		t.Fatalf("retained queue recovery: %d %v", healed, err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/cloud-entitlements/changes/"+change.ID+"/execute", operator, "a264-reviewed-execute", nil)
	if status != http.StatusAccepted {
		t.Fatalf("approved cloud enqueue: %d %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/cloud-entitlements/changes/"+change.ID, operator, nil)
	var result struct {
		State  string `json:"state"`
		Result struct {
			KeyAbsent bool `json:"key_absent"`
		} `json:"result"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &result) != nil || result.State != "verified" || !result.Result.KeyAbsent {
		t.Fatalf("native revocation readback missing: %d %s", status, body)
	}
	reader, err := awsiam.New(awsiam.Config{Endpoint: endpoint, AllowInsecureLoopback: true, UseCredentials: awsiam.SessionFile(path, nil)})
	if err != nil {
		t.Fatal(err)
	}
	capture, err := reader.Collect(t.Context(), []awsiam.Selection{{Kind: awspolicy.IAMUser, Name: "a264-change552"}})
	if err != nil || len(capture.Identities) != 1 || len(capture.Identities[0].Keys) != 0 {
		t.Fatalf("old key still present in independent IAM capture: %v", err)
	}
	// Preserve the captured conditional grant and unrelated explicit Deny. The
	// reviewed restriction goes in its own named policy; native IAM readback and
	// evaluator checks are distinct from live AWS enforcement.
	if len(value.Evaluations) != 1 || !value.Evaluations[0].Unused {
		t.Fatal("fixture did not establish an unused exact permission")
	}
	request = map[string]any{"finding_id": findings.Items[0].ID, "action": "tighten_policy", "evaluation_index": 0, "writer_session_file_ref": "env:TRSTCTL_A264_CHANGE_WRITER_PATH", "reason": "Deny this exact unused permission in all contexts", "required_approvals": 1}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/cloud-entitlements/changes", operator, "a264-tighten-proposal", request)
	var policyPlan cloudchange.Record
	if status != http.StatusCreated || json.Unmarshal(body, &policyPlan) != nil || len(policyPlan.Intent.PolicyDocument) == 0 {
		t.Fatalf("restrictive proposal: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/approval-requests/"+policyPlan.ApprovalRequestID+"/approvals", reviewer, "a264-tighten-review", map[string]any{"intent_digest": policyPlan.IntentDigest})
	if status != http.StatusOK {
		t.Fatalf("restrictive approval: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/cloud-entitlements/changes/"+policyPlan.ID+"/execute", operator, "a264-tighten-execute", nil)
	if status != http.StatusAccepted {
		t.Fatalf("restrictive enqueue: %d %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	policyPlan, err = h.store.GetCloudMachineChange(t.Context(), h.tenant, policyPlan.ID)
	if err != nil || policyPlan.State != cloudchange.Verified || policyPlan.Result == nil || !policyPlan.Result.PolicyMatches {
		t.Fatalf("native policy readback: %+v %v", policyPlan, err)
	}
	capture, err = reader.Collect(t.Context(), []awsiam.Selection{{Kind: awspolicy.IAMUser, Name: "a264-change552"}})
	if err != nil || len(capture.Identities) != 1 {
		t.Fatalf("independent policy capture: %v", err)
	}
	originalUnchanged := false
	ownedReadBack := false
	for _, receipt := range capture.Identities[0].PolicyReceipts {
		for _, original := range value.Identity.PolicyReceipts {
			if receipt.ID == original.ID && bytes.Equal(receipt.RawDocument, original.RawDocument) {
				originalUnchanged = true
			}
		}
		if bytes.Equal(receipt.RawDocument, policyPlan.Intent.PolicyDocument) {
			ownedReadBack = true
		}
	}
	after, err := assessment.Assess(capture.Identities[0], cfg.Input, time.Now().UTC())
	if err != nil || !originalUnchanged || !ownedReadBack || len(after.Evaluations) != 1 || after.Evaluations[0].Result.Decision != awspolicy.ExplicitDeny {
		t.Fatalf("restrictive readback changed original conditions/denies or failed independent model: original=%v owned=%v assessment=%+v err=%v", originalUnchanged, ownedReadBack, after, err)
	}
	// Reconciliation after completed outcomes must preserve the verified result.
	if _, err := h.srv.orch.ReconcileCloudMachineChanges(t.Context()); err != nil {
		t.Fatal(err)
	}
	replayStatus, replayBody = secretsReqKey(t, h, http.MethodPost, "/api/v1/cloud-entitlements/changes", operator, "a264-key-revoke-proposal", map[string]any{"finding_id": findings.Items[0].ID, "action": "revoke_key", "access_key_id": keyID, "writer_session_file_ref": "env:TRSTCTL_A264_CHANGE_WRITER_PATH", "reason": "Retire the exact unused fixture key after human review", "required_approvals": 1})
	if replayStatus != http.StatusCreated || !bytes.Contains(replayBody, []byte(`"state":"awaiting_approval"`)) {
		t.Fatalf("original proposal result changed after execution: %d %s", replayStatus, replayBody)
	}

	// Force RLS to reject a foreign tenant even when the SQL names our tenant.
	if err := h.store.WithTenant(t.Context(), "22222222-2222-2222-2222-222222222222", func(tx pgx.Tx) error {
		var count int
		err := tx.QueryRow(t.Context(), `SELECT count(*) FROM cloud_machine_changes WHERE tenant_id=$1`, h.tenant).Scan(&count)
		if err == nil && count != 0 {
			t.Error("foreign tenant read reviewed cloud intents")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	projector := projections.New(h.store)
	if err := projector.ProjectCatchUp(t.Context(), h.srv.log); err != nil {
		t.Fatal(err)
	}
	if _, err := projector.Snapshot(t.Context()); err != nil {
		t.Fatalf("snapshot format 97 cloud changes: %v", err)
	}
	beforeRebuild, _ := json.Marshal(policyPlan)
	if err := projector.Rebuild(t.Context(), h.srv.log); err != nil {
		t.Fatalf("cloud change immutable replay: %v", err)
	}
	rebuilt, err := h.store.GetCloudMachineChange(t.Context(), h.tenant, policyPlan.ID)
	afterRebuild, _ := json.Marshal(rebuilt)
	if err != nil || !bytes.Equal(beforeRebuild, afterRebuild) {
		t.Fatalf("rebuild changed exact reviewed intent or native result: %v", err)
	}

}
