// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/cloudentitlements/assessment"
	"trstctl.com/trstctl/internal/cloudentitlements/awsiam"
	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
	"trstctl.com/trstctl/internal/cloudentitlements/change"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/projections"
)

func TestServedApprovedCloudReplacementWaitsForExactConsumerA264(t *testing.T) {
	endpoint, path := os.Getenv("TRSTCTL_A264_IAM_ENDPOINT"), os.Getenv("TRSTCTL_A264_IAM_SESSION_FILE")
	if endpoint == "" || path == "" {
		t.Skip("owned IAM/STS endpoint, session file and a264-replace554 user/key required")
	}
	registry, _ := nativeReplacementProviderA264(t, endpoint, path, "orders-554")
	t.Setenv("TRSTCTL_A264_REPLACEMENT_READER_PATH", path)
	t.Setenv("TRSTCTL_A264_REPLACEMENT_WRITER_PATH", path)
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), allowOutboundEnvCredentialRefs("env:TRSTCTL_A264_REPLACEMENT_READER_PATH", "env:TRSTCTL_A264_REPLACEMENT_WRITER_PATH"), func(d *Deps) { d.TenantDynamicSecretProviders = registry })
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "replacement-operator", "access:write", "access:read", "discovery:read", "discovery:write", "secrets:read", "secrets:write", string(authz.PrivateEgress))
	reviewer := seedScopedTokenSubject(t, h.store, h.tenant, "replacement-reviewer", "access:approve", "access:read", "approvals:review")
	consumer := seedScopedTokenSubject(t, h.store, h.tenant, "replacement-workload", "secrets:read")
	other := seedScopedTokenSubject(t, h.store, h.tenant, "other-workload", "secrets:read")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", operator, "a264-replacement-secret", map[string]any{"name": "orders-554", "value": secret.JSONBytes([]byte("owned-fixture-placeholder"))})
	secret.Wipe(body)
	if status != http.StatusCreated {
		t.Fatalf("replacement publication seed: %d", status)
	}
	cfg := assessment.SourceConfig{Endpoint: endpoint, SessionFileRef: "env:TRSTCTL_A264_REPLACEMENT_READER_PATH", AllowPrivateEndpoint: true, PrivateEgressCIDRs: []string{serviceNowSinkCIDR(t, endpoint)}, Principals: []awsiam.Selection{{Kind: awspolicy.IAMUser, Name: "a264-replace554"}, {Kind: awspolicy.IAMRole, Name: "a264-replacement553"}}, Input: assessment.Input{Checks: []assessment.Check{{PrincipalARN: "arn:aws:iam::000000000000:user/a264-replace554", Action: "s3:GetObject", Resource: "arn:aws:s3:::a264-workload/note", ResourceAccountID: "000000000000"}, {PrincipalARN: "arn:aws:iam::000000000000:role/a264-replacement553", Action: "s3:GetObject", Resource: "arn:aws:s3:::a264-workload/note", ResourceAccountID: "000000000000"}}}}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", operator, "a264-replacement-source", map[string]any{"kind": assessment.SourceKind, "name": "owned replacement principals", "config": cfg})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil {
		t.Fatalf("replacement source: %d", status)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/runs", operator, "a264-replacement-capture", map[string]any{"source_id": source.ID})
	var run struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &run) != nil {
		t.Fatalf("replacement capture: %d", status)
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
	if status != http.StatusOK || json.Unmarshal(body, &findings) != nil || len(findings.Items) != 2 {
		t.Fatalf("replacement captured principals: %d", status)
	}
	var userFinding, roleFinding, keyID string
	for _, finding := range findings.Items {
		value, err := assessment.DecodeAssessment(finding.Metadata)
		if err != nil {
			t.Fatal(err)
		}
		switch value.Identity.Principal.Kind {
		case awspolicy.IAMUser:
			userFinding = finding.ID
			if len(value.Keys) != 1 {
				t.Fatal("owned user needs one permanent key")
			}
			keyID = value.Keys[0].Key.ID
		case awspolicy.IAMRole:
			roleFinding = finding.ID
		}
	}
	request := map[string]any{"finding_id": userFinding, "action": "replace_key", "access_key_id": keyID, "replacement_role_finding_id": roleFinding, "replacement_provider_id": "replacement-sts", "replacement_role": "orders-554", "ttl_seconds": 900, "consumer": "orders-554", "consumer_subject": "replacement-workload", "writer_session_file_ref": "env:TRSTCTL_A264_REPLACEMENT_WRITER_PATH", "reason": "Adopt the exact temporary role session before retiring this permanent key", "required_approvals": 1}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/cloud-entitlements/changes", operator, "a264-reviewed-replacement", request)
	var plan change.Record
	if status != http.StatusCreated || json.Unmarshal(body, &plan) != nil || plan.State != change.AwaitingApproval {
		t.Fatalf("approved replacement proposal unavailable: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/approval-requests/"+plan.ApprovalRequestID+"/approvals", reviewer, "a264-replacement-review", map[string]any{"intent_digest": plan.IntentDigest})
	if status != http.StatusOK {
		t.Fatalf("replacement review: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/cloud-entitlements/changes/"+plan.ID+"/execute", operator, "a264-replacement-execute", nil)
	if status != http.StatusAccepted {
		t.Fatalf("replacement enqueue: %d %s", status, body)
	}
	startServedExternalCADispatcher(t, h)
	readPlan := func() change.Record {
		t.Helper()
		status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/cloud-entitlements/changes/"+plan.ID, operator, nil)
		var current change.Record
		if status != http.StatusOK || json.Unmarshal(raw, &current) != nil {
			t.Fatal("replacement result unreadable")
		}
		return current
	}
	deadline := time.Now().Add(45 * time.Second)
	for {
		plan = readPlan()
		if plan.State == "waiting_adoption" {
			break
		}
		if plan.State == change.Failed || time.Now().After(deadline) {
			t.Fatalf("replacement did not wait for its consumer: state=%s result=%+v", plan.State, plan.Result)
		}
		time.Sleep(50 * time.Millisecond)
	}
	reader, err := awsiam.New(awsiam.Config{Endpoint: endpoint, AllowInsecureLoopback: true, UseCredentials: awsiam.SessionFile(path, nil)})
	if err != nil {
		t.Fatal(err)
	}
	assertKeys := func(want int) {
		t.Helper()
		capture, err := reader.Collect(t.Context(), []awsiam.Selection{{Kind: awspolicy.IAMUser, Name: "a264-replace554"}})
		if err != nil || len(capture.Identities) != 1 || len(capture.Identities[0].Keys) != want {
			t.Fatalf("native old-key count: want=%d err=%v", want, err)
		}
	}
	assertKeys(1)
	report := func(token, key, state string, version int) {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/deliveries", token, key, map[string]any{"consumer": "orders-554", "state": state, "secrets": []map[string]any{{"name": "orders-554", "version": version}}})
		if status != http.StatusOK {
			t.Fatalf("consumer report: %d %s", status, body)
		}
	}
	report(other, "a264-wrong-reporter", "verified", 2)
	report(consumer, "a264-injected-only", "injected", 2)
	report(consumer, "a264-wrong-version", "verified", 1)
	_, adoptionRaw := secretsReq(t, h, http.MethodGet, "/api/v1/cloud-entitlements/changes/"+plan.ID, operator, nil)
	var adoptionView map[string]json.RawMessage
	if json.Unmarshal(adoptionRaw, &adoptionView) != nil {
		t.Fatal("adoption view unreadable")
	}
	if value, ok := adoptionView["adoption"]; ok && string(value) != "null" {
		t.Fatal("unqualified reporter/version populated the replacement adoption receipt")
	}

	time.Sleep(100 * time.Millisecond)
	if current := readPlan(); current.State != "waiting_adoption" {
		t.Fatal("unqualified delivery report authorized key retirement")
	}
	assertKeys(1)
	// Roll back the adoption projection after its source event is retained. The
	// key and its retirement intent must remain untouched until replay heals it.
	if _, err := h.store.SystemPool().Exec(t.Context(), `CREATE FUNCTION cloud_adoption_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned adoption rollback'; END $$; CREATE TRIGGER cloud_adoption_fault BEFORE UPDATE ON cloud_machine_changes FOR EACH ROW WHEN (OLD.adoption IS NULL AND NEW.adoption IS NOT NULL) EXECUTE FUNCTION cloud_adoption_fault()`); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/deliveries", consumer, "a264-exact-adoption", map[string]any{"consumer": "orders-554", "state": "verified", "secrets": []map[string]any{{"name": "orders-554", "version": 2}}})
	if status != http.StatusInternalServerError {
		t.Fatalf("adoption SQL rollback was not exercised: %d %s", status, body)
	}
	assertKeys(1)
	if current := readPlan(); current.Adoption != nil || current.State != change.WaitingAdoption {
		t.Fatal("failed adoption transaction leaked retirement authority")
	}
	if _, err := h.store.SystemPool().Exec(t.Context(), `DROP TRIGGER cloud_adoption_fault ON cloud_machine_changes; DROP FUNCTION cloud_adoption_fault()`); err != nil {
		t.Fatal(err)
	}
	if err := projections.New(h.store).ProjectCatchUp(t.Context(), h.srv.log); err != nil {
		t.Fatal(err)
	}
	if current := readPlan(); current.Adoption == nil || current.Adoption.Subject != "replacement-workload" {
		t.Fatal("retained exact consumer report did not recover adoption authority")
	}

	report(other, "a264-later-injected-actor", "injected", 2)
	deadline = time.Now().Add(30 * time.Second)
	for {
		plan = readPlan()
		if plan.State == change.Verified {
			break
		}
		if plan.State == change.Failed || time.Now().After(deadline) {
			t.Fatalf("qualified replacement did not retire the captured key: state=%s result=%+v", plan.State, plan.Result)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if plan.Result == nil || !plan.Result.KeyAbsent {
		t.Fatal("replacement lacked native old-key absence readback")
	}
	assertKeys(0)
	if plan.Adoption == nil || plan.Adoption.Subject != "replacement-workload" || plan.Adoption.Version != 2 || plan.Adoption.EventID == "" {
		t.Fatal("replacement lost the original exact verified actor/version source receipt")
	}
	retained, err := h.store.GetCloudMachineChange(t.Context(), h.tenant, plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(retained)
	projector := projections.New(h.store)
	if err := projector.ProjectCatchUp(t.Context(), h.srv.log); err != nil {
		t.Fatal(err)
	}
	if _, err := projector.Snapshot(t.Context()); err != nil {
		t.Fatalf("snapshot98 replacement/adoption: %v", err)
	}
	if err := projector.Rebuild(t.Context(), h.srv.log); err != nil {
		t.Fatalf("replacement source replay: %v", err)
	}
	after, err := h.store.GetCloudMachineChange(t.Context(), h.tenant, plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, _ := json.Marshal(after)
	if !bytes.Equal(before, rebuilt) {
		t.Fatal("replay changed the exact approval, preparation or adoption/native result")
	}
}
