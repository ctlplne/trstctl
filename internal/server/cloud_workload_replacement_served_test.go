// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/agent/secretrender"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/cloudentitlements/assessment"
	"trstctl.com/trstctl/internal/cloudentitlements/awsiam"
	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
	"trstctl.com/trstctl/internal/cloudentitlements/change"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
	"trstctl.com/trstctl/internal/store"
)

func TestServedCloudReplacementKeepsStockWorkloadRunningA264(t *testing.T) {
	endpoint, path := os.Getenv("TRSTCTL_A264_IAM_ENDPOINT"), os.Getenv("TRSTCTL_A264_IAM_SESSION_FILE")
	if endpoint == "" || path == "" {
		t.Skip("owned IAM/STS endpoint, session file and a264-replace555 user/key required")
	}
	containerID, oldFile := os.Getenv("TRSTCTL_A264_WORKLOAD_CONTAINER"), os.Getenv("TRSTCTL_A264_WORKLOAD_KEY_FILE")
	if containerID == "" || oldFile == "" {
		t.Skip("owned stock-client container and private initial key file required")
	}
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(containerID) {
		t.Fatal("stock workload requires the exact owned container ID")
	}
	oldRaw, err := secretfile.LoadBounded(oldFile, 64<<10)
	if err != nil {
		t.Fatal("initial workload key file unavailable")
	}
	defer secret.Wipe(oldRaw)
	var old struct {
		AccessKey struct {
			ID     string           `json:"AccessKeyId"`
			Secret secret.JSONBytes `json:"SecretAccessKey"`
		} `json:"AccessKey"`
	}
	if json.Unmarshal(oldRaw, &old) != nil || old.AccessKey.ID == "" || len(old.AccessKey.Secret) == 0 {
		t.Fatal("initial workload key file invalid")
	}
	defer secret.Wipe(old.AccessKey.Secret)
	initial, err := json.Marshal(map[string]any{"access_key_id": old.AccessKey.ID, "secret_access_key": old.AccessKey.Secret})
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(initial)
	registry, _ := nativeReplacementProviderA264(t, endpoint, path, "orders-555")
	t.Setenv("TRSTCTL_A264_REPLACEMENT_READER_PATH", path)
	t.Setenv("TRSTCTL_A264_REPLACEMENT_WRITER_PATH", path)
	h := newOperatingServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), allowOutboundEnvCredentialRefs("env:TRSTCTL_A264_REPLACEMENT_READER_PATH", "env:TRSTCTL_A264_REPLACEMENT_WRITER_PATH"), func(d *Deps) { d.TenantDynamicSecretProviders = registry })
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "replacement-operator", "access:write", "access:read", "discovery:read", "discovery:write", "secrets:read", "secrets:write", string(authz.PrivateEgress))
	reviewer := seedScopedTokenSubject(t, h.store, h.tenant, "replacement-reviewer", "access:approve", "access:read", "approvals:review")
	consumer := seedScopedTokenSubject(t, h.store, h.tenant, "replacement-workload", "secrets:read", "secrets:write", "access:read")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", operator, "a264-workload555-secret", map[string]any{"name": "orders-555", "value": secret.JSONBytes(initial)})
	secret.Wipe(body)
	if status != http.StatusCreated {
		t.Fatalf("replacement publication seed: %d", status)
	}
	cfg := assessment.SourceConfig{Endpoint: endpoint, SessionFileRef: "env:TRSTCTL_A264_REPLACEMENT_READER_PATH", AllowPrivateEndpoint: true, PrivateEgressCIDRs: []string{serviceNowSinkCIDR(t, endpoint)}, Principals: []awsiam.Selection{{Kind: awspolicy.IAMUser, Name: "a264-replace555"}, {Kind: awspolicy.IAMRole, Name: "a264-replacement553"}}, Input: assessment.Input{Checks: []assessment.Check{{PrincipalARN: "arn:aws:iam::000000000000:user/a264-replace555", Action: "s3:GetObject", Resource: "arn:aws:s3:::a264-workload/note", ResourceAccountID: "000000000000"}, {PrincipalARN: "arn:aws:iam::000000000000:role/a264-replacement553", Action: "s3:GetObject", Resource: "arn:aws:s3:::a264-workload/note", ResourceAccountID: "000000000000"}}}}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", operator, "a264-workload555-source", map[string]any{"kind": assessment.SourceKind, "name": "owned replacement principals", "config": cfg})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil {
		t.Fatalf("replacement source: %d", status)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/runs", operator, "a264-workload555-capture", map[string]any{"source_id": source.ID})
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
	dir := t.TempDir()
	credentialFile := filepath.Join(dir, "workload.json")
	client, err := secretrender.NewSessionHTTPClient(h.ts.URL, h.tenant, []byte(consumer), h.ts.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Wipe()
	var workloadMu sync.Mutex
	var successful int
	seen := map[string]string{}
	requestWorkload := func() error {
		workloadMu.Lock()
		defer workloadMu.Unlock()
		raw, err := secretfile.LoadBounded(credentialFile, 64<<10)
		if err != nil {
			return err
		}
		defer secret.Wipe(raw)
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "docker", "exec", "-i", containerID, "python3", "-c", stockCloudWorkloadA264) // #nosec G204 G702 -- validated 64-hex owned test container ID and constant stock-client program, separate argv, no shell (CWE-78)
		cmd.Stdin = bytes.NewReader(raw)
		out, err := cmd.Output()
		if err != nil {
			return errors.New("stock workload resource request failed")
		}
		var proof struct {
			Key  string `json:"key"`
			ARN  string `json:"arn"`
			Note string `json:"note"`
		}
		if json.Unmarshal(out, &proof) != nil || proof.Note != "owned A264 workload proof" || proof.Key == "" {
			return errors.New("stock workload readback invalid")
		}
		successful++
		seen[proof.Key] = proof.ARN
		return nil
	}
	application := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requestWorkload() != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer application.Close()
	cfgRender := secretrender.Config{Server: h.ts.URL, TokenFile: "session", Tenant: h.tenant, Consumer: "orders-555", StateDir: filepath.Join(dir, "state"), Interval: 2 * time.Second, Templates: []secretrender.Template{{Name: "orders", Destination: credentialFile, Text: `{{ secret "orders-555" }}`, Verify: secretrender.Verify{URL: application.URL, Timeout: 5 * time.Second}}}}
	initialRenderer, err := secretrender.New(cfgRender, client, client, nil)
	if err != nil {
		t.Fatal(err)
	}
	initialRenderer.Once(t.Context())
	if err := requestWorkload(); err != nil {
		t.Fatal("initial product-rendered workload unavailable")
	}
	request := map[string]any{"finding_id": userFinding, "action": "replace_key", "access_key_id": keyID, "replacement_role_finding_id": roleFinding, "replacement_provider_id": "replacement-sts", "replacement_role": "orders-555", "ttl_seconds": 900, "consumer": "orders-555", "consumer_subject": "replacement-workload", "writer_session_file_ref": "env:TRSTCTL_A264_REPLACEMENT_WRITER_PATH", "reason": "Adopt the exact temporary role session before retiring this permanent key", "required_approvals": 1}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/cloud-entitlements/changes", operator, "a264-reviewed-workload555", request)
	var plan change.Record
	if status != http.StatusCreated || json.Unmarshal(body, &plan) != nil || plan.State != change.AwaitingApproval {
		t.Fatalf("approved replacement proposal unavailable: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/approval-requests/"+plan.ApprovalRequestID+"/approvals", reviewer, "a264-workload555-review", map[string]any{"intent_digest": plan.IntentDigest})
	if status != http.StatusOK {
		t.Fatalf("replacement review: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/cloud-entitlements/changes/"+plan.ID+"/execute", operator, "a264-workload555-execute", nil)
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

	cfgRender.Templates[0].Text = `{{ lease "replacement-sts/orders-555" }}`
	cfgRender.Templates[0].LeaseTTL = 15 * time.Minute
	cfgRender.Templates[0].Replacement = &secretrender.ReplacementBootstrap{ChangeID: plan.ID, Provider: "replacement-sts", Role: "orders-555"}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	renderer, err := secretrender.New(cfgRender, client, client, logger)
	if err != nil {
		t.Fatal(err)
	}
	renderer.UseLeases(client)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _ = renderer.Run(ctx) }()
	defer func() { cancel(); <-done }()
	reader, err := awsiam.New(awsiam.Config{Endpoint: endpoint, AllowInsecureLoopback: true, UseCredentials: awsiam.SessionFile(path, nil)})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		plan = readPlan()
		if plan.State == change.Verified {
			break
		}
		if plan.State == change.Failed || time.Now().After(deadline) {
			t.Fatalf("real workload replacement did not verify: %s %+v", plan.State, plan.Result)
		}
		if err := requestWorkload(); err != nil {
			t.Fatal("workload stopped during replacement")
		}
		time.Sleep(200 * time.Millisecond)
	}
	capture, err := reader.Collect(t.Context(), []awsiam.Selection{{Kind: awspolicy.IAMUser, Name: "a264-replace555"}})
	if err != nil || len(capture.Identities) != 1 || len(capture.Identities[0].Keys) != 0 || plan.Adoption == nil || plan.Adoption.Version != 2 || plan.Adoption.Subject != "replacement-workload" {
		t.Fatal("native key absence or exact verified adoption missing")
	}
	minimum := 2
	if os.Getenv("TRSTCTL_A264_REFRESH_PROOF") == "1" {
		minimum = 4
		deadline = time.Now().Add(35 * time.Minute)
	} else {
		deadline = time.Now().Add(15 * time.Second)
	}
	for {
		if err := requestWorkload(); err != nil {
			t.Fatal("workload stopped after native old-key deletion")
		}
		workloadMu.Lock()
		count := len(seen)
		calls := successful
		workloadMu.Unlock()
		if count >= minimum && calls >= 8 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("unattended workload refresh incomplete: distinct credentials=%d required=%d", count, minimum)
		}
		time.Sleep(time.Second)
	}
	if minimum == 4 {
		first, err := h.store.GetDynamicSecretLease(t.Context(), h.tenant, plan.Result.ReplacementLeaseID)
		if err != nil || first.State != store.DynamicSecretLeaseRevoked || first.RevocationStatus != store.DynamicSecretRevocationCompleted || first.RevocationMethod != "native_expiry" || first.RevocationCompletedAt == nil || first.RevocationCompletedAt.Before(*plan.Result.ReplacementExpiresAt) {
			t.Fatalf("first replaced STS lease did not complete truthful native-expiry retirement: state=%s revocation=%s method=%s err=%v", first.State, first.RevocationStatus, first.RevocationMethod, err)
		}
	}
	workloadMu.Lock()
	defer workloadMu.Unlock()
	for key, arn := range seen {
		if key != old.AccessKey.ID && !strings.HasPrefix(arn, "arn:aws:sts::000000000000:assumed-role/a264-replacement553/") {
			t.Fatal("workload used an unexpected native role")
		}
	}
	t.Logf("stock boto3 resource readback: successful_requests=%d distinct_credentials=%d old_key_absent=true exact_adoption_version=2", successful, len(seen))
}

const stockCloudWorkloadA264 = `
import sys,json,boto3
from botocore.config import Config
c=json.load(sys.stdin)
args=dict(aws_access_key_id=c["access_key_id"],aws_secret_access_key=c["secret_access_key"],aws_session_token=c.get("session_token"),region_name="us-east-1",endpoint_url="http://127.0.0.1:4566",config=Config(retries={"max_attempts":0},connect_timeout=2,read_timeout=2))
note=boto3.client("s3",**args).get_object(Bucket="a264-workload",Key="note")["Body"].read().decode()
arn=boto3.client("sts",**args).get_caller_identity()["Arn"]
print(json.dumps(dict(key=c["access_key_id"],arn=arn,note=note)))
`
