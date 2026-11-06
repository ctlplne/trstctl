// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"encoding/json"
	"github.com/google/uuid"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/egress"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/cloudentitlements/assessment"
	"trstctl.com/trstctl/internal/cloudentitlements/awsiam"
	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
	"trstctl.com/trstctl/internal/config"
)

func TestServedCloudMachineEntitlementCaptureA264(t *testing.T) {
	endpoint := os.Getenv("TRSTCTL_A264_IAM_ENDPOINT")
	sessionPath := os.Getenv("TRSTCTL_A264_IAM_SESSION_FILE")
	if endpoint == "" || sessionPath == "" {
		t.Skip("owned LocalStack IAM endpoint and private session file required")
	}
	t.Setenv("TRSTCTL_A264_READER_SESSION_PATH", sessionPath)
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs("env:TRSTCTL_A264_READER_SESSION_PATH"))
	writer := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "nhi:read", "graph:read", "access:write", "access:read", string(authz.PrivateEgress))
	arn := "arn:aws:iam::000000000000:user/a264-workload"
	resource := "arn:aws:s3:::a264-workload/note"
	now := time.Now().UTC()
	cfg := assessment.SourceConfig{Endpoint: endpoint, SessionFileRef: "env:TRSTCTL_A264_READER_SESSION_PATH", AllowPrivateEndpoint: true, PrivateEgressCIDRs: []string{serviceNowSinkCIDR(t, endpoint)}, Principals: []awsiam.Selection{{Kind: awspolicy.IAMUser, Name: "a264-workload"}}, Input: assessment.Input{Checks: []assessment.Check{{PrincipalARN: arn, Action: "s3:GetObject", Resource: resource, ResourceAccountID: "000000000000", Context: awspolicy.Context{Complete: true, Values: map[string][]string{"aws:TokenIssueTime": {"2026-11-05T00:00:00Z"}}}}}, Supplemental: []assessment.Supplemental{{PrincipalARN: arn, SourceRef: "recorded:local-organization-fixture", Resource: resource, ResourceAccountID: "000000000000", ResourcePolicies: assessment.PolicySet{Coverage: awspolicy.Absent}, SCPCoverage: awspolicy.Absent, RCPCoverage: awspolicy.Absent}}, Activity: assessment.ActivityEvidence{SourceRef: "recorded:local-cloudtrail-data-window", Start: now.Add(-30 * 24 * time.Hour), End: now, Scopes: []assessment.ActivityScope{{PrincipalARN: arn, Action: "s3:GetObject", Resource: resource, Complete: true}}}}}

	unapproved := cfg
	unapproved.SessionFileRef = "env:TRSTCTL_A264_UNAPPROVED_SESSION_PATH"
	status, deniedBody := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", writer, "a264-unapproved-reference", map[string]any{"kind": assessment.SourceKind, "name": "unapproved IAM reader", "config": unapproved})
	if status != http.StatusBadRequest {
		t.Fatalf("unapproved session reference accepted: %d %s", status, deniedBody)
	}
	status, previewBody := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/plans/preview", writer, map[string]any{"kind": assessment.SourceKind, "name": "owned AWS workload entitlement", "config": cfg})
	if status != http.StatusOK || !bytes.Contains(previewBody, []byte(`"normalized_target_count":1`)) || !bytes.Contains(previewBody, []byte(`"estimated_upper_seconds":300`)) {
		t.Fatalf("exact native capture preview missing: %d %s", status, previewBody)
	}

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", writer, "a264-native-source", map[string]any{"kind": assessment.SourceKind, "name": "owned AWS workload entitlement", "config": cfg})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil || source.ID == "" {
		t.Fatalf("declare cloud machine source: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/runs", writer, "a264-native-run", map[string]any{"source_id": source.ID})
	var queued struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &queued) != nil || queued.ID == "" {
		t.Fatalf("queue cloud machine capture: %d %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	run, err := h.store.GetDiscoveryRun(t.Context(), h.tenant, queued.ID)
	if err != nil || run.Status != "succeeded" || run.Discovered != 1 {
		t.Fatalf("capture run: %+v %v", run, err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+queued.ID, writer, nil)
	var findings struct {
		Items []struct {
			ID          string          `json:"id"`
			Kind        string          `json:"kind"`
			Fingerprint string          `json:"fingerprint"`
			Metadata    json.RawMessage `json:"metadata"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &findings) != nil || len(findings.Items) != 1 {
		t.Fatalf("captured findings: %d %s", status, body)
	}
	value, err := assessment.DecodeAssessment(findings.Items[0].Metadata)
	if err != nil {
		t.Fatal(err)
	}
	if len(value.Evaluations) != 1 || value.Evaluations[0].Result.Decision != awspolicy.Allowed || !value.Evaluations[0].Unused || len(value.Keys) != 1 || value.Identity.Principal.ARN != arn {
		t.Fatalf("native/recorded assessment: %+v", value)
	}
	target := "res:aws:" + resource
	status, graphBody := secretsReq(t, h, http.MethodGet, "/api/v1/graph/reachers/"+url.PathEscape(target), writer, nil)
	if status != http.StatusOK || !bytes.Contains(graphBody, []byte(`"confidence":"policy_model"`)) || !bytes.Contains(graphBody, []byte(arn)) {
		t.Fatalf("captured IAM model missing from G1/G2: %d %s", status, graphBody)
	}
	status, reviewBody := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/reviews/generate", writer, "a264-review", map[string]any{"name": "Review captured workload IAM access", "source": "graph_reachers", "target": target})
	if status != http.StatusCreated || !bytes.Contains(reviewBody, []byte("cloud machine policy model finding")) {
		t.Fatalf("Q1 review lost captured policy provenance: %d %s", status, reviewBody)
	}
	digest, err := assessment.Fingerprint(value)
	if err != nil || digest != findings.Items[0].Fingerprint {
		t.Fatal("immutable source evidence fingerprint absent")
	}
	// A correctly hashed manual import cannot displace native provenance. The
	// generic manual-input guard excludes token-named public context keys; omit
	// that hypothetical key from this independent counterfeit and re-hash it.
	spoofValue := value
	spoofValue.Evaluations = append([]assessment.Evaluation(nil), value.Evaluations...)
	for i := range spoofValue.Evaluations {
		spoofValue.Evaluations[i].Check.Context.Values = nil
	}
	spoofValue.CapturedInput.Checks = append([]assessment.Check(nil), value.CapturedInput.Checks...)
	for i := range spoofValue.CapturedInput.Checks {
		spoofValue.CapturedInput.Checks[i].Context.Values = nil
	}
	spoofDigest, err := assessment.Fingerprint(spoofValue)
	if err != nil {
		t.Fatal(err)
	}
	status, spoofBody := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", writer, "a264-manual-counterfeit", map[string]any{"kind": "manual", "name": "counterfeit native IAM snapshot", "config": map[string]any{"findings": []map[string]any{{"kind": assessment.FindingKind, "ref": "aws-iam:" + arn, "provenance": "aws-iam:000000000000", "fingerprint": spoofDigest, "metadata": spoofValue}}}})
	var spoofSource struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(spoofBody, &spoofSource) != nil {
		t.Fatalf("manual counterexample fixture: %d %s", status, spoofBody)
	}
	status, spoofBody = secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/runs", writer, "a264-manual-counterfeit-run", map[string]any{"source_id": spoofSource.ID})
	if status != http.StatusCreated {
		t.Fatalf("manual counterexample queue: %d %s", status, spoofBody)
	}
	var spoofRun struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(spoofBody, &spoofRun) != nil || spoofRun.ID == "" {
		t.Fatal("manual counterexample run has no identity")
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, manualBody := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+spoofRun.ID, writer, nil)
	var manual struct {
		Items []struct {
			Kind        string          `json:"kind"`
			Fingerprint string          `json:"fingerprint"`
			Metadata    json.RawMessage `json:"metadata"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(manualBody, &manual) != nil || len(manual.Items) != 1 || manual.Items[0].Kind != assessment.FindingKind || manual.Items[0].Fingerprint != spoofDigest {
		t.Fatalf("manual counterexample was not recorded: %d %s", status, manualBody)
	}
	copied, err := assessment.DecodeAssessment(manual.Items[0].Metadata)
	if err != nil {
		t.Fatal(err)
	}
	copiedDigest, err := assessment.Fingerprint(copied)
	if err != nil || copiedDigest != spoofDigest {
		t.Fatal("manual counterexample lacks valid typed fingerprint")
	}
	status, graphBody = secretsReq(t, h, http.MethodGet, "/api/v1/graph/reachers/"+url.PathEscape(target), writer, nil)
	if status != http.StatusOK || !bytes.Contains(graphBody, []byte("cloud machine policy model finding "+findings.Items[0].ID)) {
		t.Fatalf("manual import displaced verified native model: %d %s", status, graphBody)
	}
	status, nhiBody := secretsReq(t, h, http.MethodGet, "/api/v1/nhi/inventory", writer, nil)
	if status != http.StatusOK || !bytes.Contains(nhiBody, []byte(`"kind":"service_account"`)) || !bytes.Contains(nhiBody, []byte(arn)) {
		t.Fatalf("native IAM user kind absent from NHI: %d %s", status, nhiBody)
	}
	other := uuid.NewString()
	registerServedTenantID(t, h, other, "Cloud machine isolation tenant")
	otherToken := seedScopedToken(t, h.store, other, "discovery:read", "graph:read", "nhi:read")
	for _, path := range []string{"/api/v1/discovery/findings?run_id=" + queued.ID, "/api/v1/graph", "/api/v1/nhi/inventory"} {
		status, foreignBody := secretsReq(t, h, http.MethodGet, path, otherToken, nil)
		if status != http.StatusOK || bytes.Contains(foreignBody, []byte(arn)) {
			t.Fatalf("another tenant read captured IAM facts: %s %d %s", path, status, foreignBody)
		}
	}
	// Use a logical metadata clock, never the host or authentication clock.
	dispatcher := h.srv.obHandler.(*issuanceDispatcher)
	dispatcher.cloudEntitlementNow = func() time.Time { return now.Add(91 * 24 * time.Hour) }
	defer func() { dispatcher.cloudEntitlementNow = nil }()
	cfg.Input.Supplemental[0].SCPCoverage = awspolicy.Complete
	cfg.Input.Supplemental[0].SCP = []assessment.PolicySet{{Coverage: awspolicy.Complete, Documents: []json.RawMessage{json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"s3:GetObject","Resource":"*","Condition":{"DateGreaterThan":{"aws:TokenIssueTime":"2020-01-01T00:00:00Z"}}}]}`)}}}
	status, updateBody := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", writer, "a264-recorded-guard-update", map[string]any{"kind": assessment.SourceKind, "name": "owned AWS workload entitlement", "config": cfg})
	if status != http.StatusCreated {
		t.Fatalf("recorded condition guard update: %d %s", status, updateBody)
	}
	status, runBody := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/runs", writer, "a264-stale-guard-run", map[string]any{"source_id": source.ID})
	var second struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(runBody, &second) != nil {
		t.Fatalf("recorded condition guard queue: %d %s", status, runBody)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+second.ID, writer, nil)
	if status != http.StatusOK || json.Unmarshal(body, &findings) != nil || len(findings.Items) != 1 {
		t.Fatalf("recorded condition/stale findings: %d %s", status, body)
	}
	value, err = assessment.DecodeAssessment(findings.Items[0].Metadata)
	if err != nil || len(value.Keys) != 1 || !value.Keys[0].Stale || !value.Keys[0].LongLived || value.Evaluations[0].Result.Decision != awspolicy.ExplicitDeny || value.Evaluations[0].Unused {
		t.Fatalf("logical age and conditional organization deny: %+v %v", value, err)
	}
	status, graphBody = secretsReq(t, h, http.MethodGet, "/api/v1/graph/reachers/"+url.PathEscape(target), writer, nil)
	var reachers struct {
		Access []json.RawMessage `json:"access"`
	}
	if status != http.StatusOK || json.Unmarshal(graphBody, &reachers) != nil || len(reachers.Access) != 0 {
		t.Fatalf("previous Allow survived latest captured Deny: %d %s", status, graphBody)
	}
	guard, err := egress.NewGuard(egress.Config{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.egress = guard
	status, runBody = secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/runs", writer, "a264-airgap-run", map[string]any{"source_id": source.ID})
	var blocked struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(runBody, &blocked) != nil {
		t.Fatalf("air-gap queue: %d %s", status, runBody)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	blockedRun, err := h.store.GetDiscoveryRun(t.Context(), h.tenant, blocked.ID)
	if err != nil || blockedRun.Status != "failed" || blockedRun.Discovered != 0 || guard.Trips() == 0 {
		t.Fatalf("air-gap run did not refuse capture: %+v %v", blockedRun, err)
	}

}
