// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/egress"
)

// TestServedCloudAccessKeyDiscoveryFlagsNinetyDaysUnusedM3 is M3 on LocalStack
// IAM, through a cloud_access_key source configured as an operator configures
// one: every user's access key appears with its owner, status, age and last
// use; a run measured 91 days on flags the two active keys nobody has used
// since (one last used, one never used) and not the inactive one; no secret
// access key reaches a finding or the API; the keys show in the NHI inventory
// as API keys; another tenant sees none of it; and with the air-gap guard
// enforcing, the run reaches nothing and records nothing.
func TestServedCloudAccessKeyDiscoveryFlagsNinetyDaysUnusedM3(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	localstack, address := a201Container(t, "4566", "-e", "SERVICES=iam", a202LocalStackImage)
	a201Await(t, "LocalStack IAM", func() bool {
		_, err := a201Exec(localstack, "awslocal", "iam", "list-users")
		return err == nil
	})
	awslocal := func(env []string, args ...string) string {
		t.Helper()
		cmd := append([]string{}, env...)
		cmd = append(cmd, "awslocal")
		out, err := a201Exec(localstack, append(cmd, args...)...)
		if err != nil {
			t.Fatalf("awslocal %v: %v %s", args, err, out)
		}
		return out
	}
	type created struct {
		AccessKey struct {
			AccessKeyID     string `json:"AccessKeyId"`
			SecretAccessKey string `json:"SecretAccessKey"`
		} `json:"AccessKey"`
	}
	newKey := func(user string) created {
		t.Helper()
		var c created
		if err := json.Unmarshal([]byte(awslocal(nil, "iam", "create-access-key", "--user-name", user)), &c); err != nil || c.AccessKey.AccessKeyID == "" {
			t.Fatalf("create access key for %s: %v", user, err)
		}
		return c
	}
	awslocal(nil, "iam", "create-user", "--user-name", "m3-ci-deployer")
	awslocal(nil, "iam", "create-user", "--user-name", "m3-backup-job")
	used, unused, inactive := newKey("m3-ci-deployer"), newKey("m3-backup-job"), newKey("m3-backup-job")
	awslocal(nil, "iam", "update-access-key", "--user-name", "m3-backup-job", "--access-key-id", inactive.AccessKey.AccessKeyID, "--status", "Inactive")
	// Use one key once, as a workload would, so IAM records its last use.
	exec := []string{"env", "AWS_ACCESS_KEY_ID=" + used.AccessKey.AccessKeyID, "AWS_SECRET_ACCESS_KEY=" + used.AccessKey.SecretAccessKey}
	awslocal(exec, "iam", "get-user")
	secrets := []string{used.AccessKey.SecretAccessKey, unused.AccessKey.SecretAccessKey, inactive.AccessKey.SecretAccessKey}

	t.Setenv("TRSTCTL_M3_IAM_ACCESS_KEY_ID", "test")
	t.Setenv("TRSTCTL_M3_IAM_SECRET_ACCESS_KEY", "test")
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs(
		"env:TRSTCTL_M3_IAM_ACCESS_KEY_ID", "env:TRSTCTL_M3_IAM_SECRET_ACCESS_KEY"))
	ctx := t.Context()
	writer := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "nhi:read", string(authz.PrivateEgress))
	endpoint := "http://" + address
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", writer, map[string]any{
		"name": "aws-iam-keys", "kind": "cloud_access_key", "config": map[string]any{"providers": []map[string]any{{ // #nosec G101 -- credential references only; no credential value enters the config (CWE-798)
			"provider": "aws-iam", "endpoint": endpoint, "allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, endpoint)},
			"access_key_id_ref": "env:TRSTCTL_M3_IAM_ACCESS_KEY_ID", "secret_access_key_ref": "env:TRSTCTL_M3_IAM_SECRET_ACCESS_KEY",
		}}},
	})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil || source.ID == "" {
		t.Fatalf("create cloud_access_key source: %d %s", status, body)
	}

	type finding struct {
		Kind        string         `json:"kind"`
		Ref         string         `json:"ref"`
		Fingerprint string         `json:"fingerprint"`
		RiskScore   int            `json:"risk_score"`
		Metadata    map[string]any `json:"metadata"`
	}
	runAt := func(key string) (string, map[string]finding) {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/runs", writer, key, map[string]any{"source_id": source.ID})
		var queued struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &queued) != nil || queued.ID == "" {
			t.Fatalf("queue %s: %d %s", key, status, body)
		}
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatalf("drain %s: %v", key, err)
		}
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+queued.ID, writer, nil)
		var listed struct {
			Items []finding `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &listed) != nil {
			t.Fatalf("findings of %s: %d %s", key, status, body)
		}
		for _, s := range secrets {
			if bytes.Contains(body, []byte(s)) {
				t.Fatalf("a secret access key reached the findings API")
			}
		}
		byKey := map[string]finding{}
		for _, f := range listed.Items {
			byKey[f.Metadata["access_key_id"].(string)] = f
		}
		return queued.ID, byKey
	}

	// Today: three keys with owner, status, age and last use; none stale.
	runID, today := runAt("m3-today")
	run, err := h.store.GetDiscoveryRun(ctx, h.tenant, runID)
	if err != nil || run.Status != "succeeded" || run.Targets != 1 || run.Discovered != 3 || len(today) != 3 {
		t.Fatalf("today's run = %+v %v findings=%v", run, err, today)
	}
	u := today[used.AccessKey.AccessKeyID]
	if u.Kind != "cloud_access_key" || u.Metadata["user"] != "m3-ci-deployer" || u.Metadata["status"] != "Active" || u.Metadata["last_used_service"] != "iam" ||
		u.Metadata["last_used_at"] == nil || u.Metadata["age_days"] != float64(0) || u.Metadata["stale"] != false || u.RiskScore != 30 ||
		u.Ref != "aws-iam:m3-ci-deployer:"+used.AccessKey.AccessKeyID || u.Fingerprint != "aws-iam:"+used.AccessKey.AccessKeyID {
		t.Fatalf("the used key today = %+v", u)
	}
	n := today[unused.AccessKey.AccessKeyID]
	if n.Metadata["user"] != "m3-backup-job" || n.Metadata["never_used"] != true || n.Metadata["last_used_at"] != nil || n.Metadata["stale"] != false || n.Metadata["created_at"] == nil {
		t.Fatalf("the never-used key today = %+v", n)
	}
	if off := today[inactive.AccessKey.AccessKeyID]; off.Metadata["status"] != "Inactive" || off.Metadata["stale"] != false {
		t.Fatalf("the inactive key today = %+v", off)
	}

	// 91 days on: both active keys are unused for 90 days and flagged; the
	// inactive key is not.
	dispatcher := h.srv.obHandler.(*issuanceDispatcher)
	later := time.Now().Add(91 * 24 * time.Hour)
	dispatcher.accessKeyNow = func() time.Time { return later }
	_, aged := runAt("m3-91-days")
	for _, id := range []string{used.AccessKey.AccessKeyID, unused.AccessKey.AccessKeyID} {
		f := aged[id]
		if f.Metadata["stale"] != true || f.RiskScore != 80 || f.Metadata["unused_days"].(float64) < 90 || f.Metadata["age_days"].(float64) < 90 {
			t.Fatalf("an active key unused for 91 days is not flagged: %+v", f)
		}
	}
	if off := aged[inactive.AccessKey.AccessKeyID]; off.Metadata["stale"] != false || off.RiskScore != 30 {
		t.Fatalf("the inactive key is flagged: %+v", off)
	}
	dispatcher.accessKeyNow = nil

	// The keys feed the NHI inventory as API keys.
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/nhi/inventory", writer, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"kind":"api_key"`) || !strings.Contains(string(body), unused.AccessKey.AccessKeyID) {
		t.Fatalf("NHI inventory after cloud access-key discovery = %d %s", status, body)
	}

	// Another tenant sees no key, run or source.
	other := uuid.NewString()
	registerServedTenantID(t, h, other, "M3 isolation tenant")
	otherToken := seedScopedToken(t, h.store, other, "discovery:read", "nhi:read")
	for _, path := range []string{"/api/v1/discovery/findings?run_id=" + runID, "/api/v1/nhi/inventory", "/api/v1/discovery/sources"} {
		status, body := secretsReq(t, h, http.MethodGet, path, otherToken, nil)
		if bytes.Contains(body, []byte(used.AccessKey.AccessKeyID)) || bytes.Contains(body, []byte(source.ID)) || bytes.Contains(body, []byte("m3-backup-job")) {
			t.Fatalf("another tenant read M3 data at %s: %d %s", path, status, body)
		}
	}

	// Air gap enforcing with no allowance: the run reaches nothing.
	guard, err := egress.NewGuard(egress.Config{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.egress = guard
	blockedID, blocked := runAt("m3-air-gapped")
	run, err = h.store.GetDiscoveryRun(ctx, h.tenant, blockedID)
	if err != nil || run.Status != "failed" || run.Discovered != 0 || len(blocked) != 0 || guard.Trips() == 0 {
		t.Fatalf("air-gapped run = %+v %v findings=%v trips=%d", run, err, blocked, guard.Trips())
	}
}

// m3l1IAMStandIn is AWS IAM's Query API (ListUsers, ListAccessKeys,
// GetAccessKeyLastUsed; version 2010-05-08), written from AWS's public API
// reference: two users across two ListUsers pages, a key used two days ago,
// an active key never used, and an inactive key. It keeps every request's
// Authorization header and body.
type m3l1IAMStandIn struct {
	now  time.Time
	mu   sync.Mutex
	seen []string
}

func (s *m3l1IAMStandIn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(raw))
	s.mu.Lock()
	s.seen = append(s.seen, r.Header.Get("Authorization")+"\n"+string(raw))
	s.mu.Unlock()
	if form.Get("Version") != "2010-05-08" || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=m3l1-reader/") {
		http.Error(w, "unsigned or wrong version", http.StatusForbidden)
		return
	}
	day := func(d int) string { return s.now.AddDate(0, 0, d).Format(time.RFC3339) }
	key := func(user, id, status, created string) string {
		return "<member><UserName>" + user + "</UserName><AccessKeyId>" + id + "</AccessKeyId><Status>" + status + "</Status><CreateDate>" + created + "</CreateDate></member>"
	}
	w.Header().Set("Content-Type", "text/xml")
	switch form.Get("Action") {
	case "ListUsers":
		if form.Get("Marker") == "" {
			_, _ = io.WriteString(w, `<ListUsersResponse><ListUsersResult><Users><member><UserName>m3-ci-deployer</UserName><Arn>arn:aws:iam::123456789012:user/ci/m3-ci-deployer</Arn></member></Users><IsTruncated>true</IsTruncated><Marker>page-2</Marker></ListUsersResult></ListUsersResponse>`)
			return
		}
		_, _ = io.WriteString(w, `<ListUsersResponse><ListUsersResult><Users><member><UserName>m3-backup-job</UserName><Arn>arn:aws:iam::123456789012:user/m3-backup-job</Arn></member></Users><IsTruncated>false</IsTruncated></ListUsersResult></ListUsersResponse>`)
	case "ListAccessKeys":
		var keys string
		switch form.Get("UserName") {
		case "m3-ci-deployer":
			keys = key("m3-ci-deployer", "m3l1-key-used", "Active", day(-10))
		case "m3-backup-job":
			keys = key("m3-backup-job", "m3l1-key-never", "Active", day(-5)) + key("m3-backup-job", "m3l1-key-off", "Inactive", day(-200))
		default:
			http.Error(w, "NoSuchEntity", http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, `<ListAccessKeysResponse><ListAccessKeysResult><AccessKeyMetadata>`+keys+`</AccessKeyMetadata><IsTruncated>false</IsTruncated></ListAccessKeysResult></ListAccessKeysResponse>`)
	case "GetAccessKeyLastUsed":
		if form.Get("AccessKeyId") == "m3l1-key-used" {
			_, _ = io.WriteString(w, `<GetAccessKeyLastUsedResponse><GetAccessKeyLastUsedResult><UserName>m3-ci-deployer</UserName><AccessKeyLastUsed><LastUsedDate>`+day(-2)+`</LastUsedDate><ServiceName>iam</ServiceName><Region>us-east-1</Region></AccessKeyLastUsed></GetAccessKeyLastUsedResult></GetAccessKeyLastUsedResponse>`)
			return
		}
		// A key never used: IAM answers N/A for the service and region and no date.
		_, _ = io.WriteString(w, `<GetAccessKeyLastUsedResponse><GetAccessKeyLastUsedResult><AccessKeyLastUsed><ServiceName>N/A</ServiceName><Region>N/A</Region></AccessKeyLastUsed></GetAccessKeyLastUsedResult></GetAccessKeyLastUsedResponse>`)
	default:
		http.Error(w, "InvalidAction", http.StatusBadRequest)
	}
}

// TestServedCloudAccessKeyDiscoveryReadsAWSKeysOnAnIAMStandInM3L1 keeps the
// AWS path served without a LocalStack container: M3-L1 moved every
// provider's keys through one record path, and an aws-iam provider still
// records each key with its owner, status, age and last use (service and
// region included). An active key unused for 90 days, or never used 90 days
// after creation, is stale with risk 80; an inactive key never is. Requests
// are signed, and the secret access key never travels or reaches a finding.
func TestServedCloudAccessKeyDiscoveryReadsAWSKeysOnAnIAMStandInM3L1(t *testing.T) {
	iam := &m3l1IAMStandIn{now: time.Now().UTC()}
	srv := httptest.NewServer(iam)
	t.Cleanup(srv.Close)
	const signingSecret = "m3l1-standin-signing-value" // #nosec G101 -- the test's own stand-in signing value, not a credential (CWE-798)
	t.Setenv("TRSTCTL_M3L1_IAM_ACCESS_KEY_ID", "m3l1-reader")
	t.Setenv("TRSTCTL_M3L1_IAM_SECRET_ACCESS_KEY", signingSecret)
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs(
		"env:TRSTCTL_M3L1_IAM_ACCESS_KEY_ID", "env:TRSTCTL_M3L1_IAM_SECRET_ACCESS_KEY"))
	ctx := t.Context()
	writer := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "nhi:read", string(authz.PrivateEgress))
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", writer, map[string]any{
		"name": "aws-iam-keys-standin", "kind": "cloud_access_key", "config": map[string]any{"providers": []map[string]any{{ // #nosec G101 -- credential references only; no credential value enters the config (CWE-798)
			"provider": "aws-iam", "endpoint": srv.URL, "allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, srv.URL)},
			"access_key_id_ref": "env:TRSTCTL_M3L1_IAM_ACCESS_KEY_ID", "secret_access_key_ref": "env:TRSTCTL_M3L1_IAM_SECRET_ACCESS_KEY",
		}}},
	})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil || source.ID == "" {
		t.Fatalf("create the aws-iam cloud_access_key source: %d %s", status, body)
	}
	type finding struct {
		Ref         string         `json:"ref"`
		Fingerprint string         `json:"fingerprint"`
		RiskScore   int            `json:"risk_score"`
		Metadata    map[string]any `json:"metadata"`
	}
	runAt := func(key string) map[string]finding {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/runs", writer, key, map[string]any{"source_id": source.ID})
		var queued struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &queued) != nil || queued.ID == "" {
			t.Fatalf("queue %s: %d %s", key, status, body)
		}
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatalf("drain %s: %v", key, err)
		}
		if run, err := h.store.GetDiscoveryRun(ctx, h.tenant, queued.ID); err != nil || run.Status != "succeeded" {
			t.Fatalf("run %s = %+v, %v", key, run, err)
		}
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+queued.ID, writer, nil)
		var listed struct {
			Items []finding `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &listed) != nil || bytes.Contains(body, []byte(signingSecret)) {
			t.Fatalf("findings of %s: %d %s", key, status, body)
		}
		byKey := map[string]finding{}
		for _, f := range listed.Items {
			byKey[f.Metadata["access_key_id"].(string)] = f
		}
		return byKey
	}

	today := runAt("m3l1-aws-today")
	if len(today) != 3 {
		t.Fatalf("today = %d keys: %v", len(today), today)
	}
	u := today["m3l1-key-used"]
	if u.Metadata["provider"] != "aws-iam" || u.Metadata["user"] != "m3-ci-deployer" || u.Metadata["status"] != "Active" ||
		u.Metadata["last_used_service"] != "iam" || u.Metadata["last_used_region"] != "us-east-1" || u.Metadata["last_used_at"] == nil ||
		u.Metadata["age_days"] != float64(10) || u.Metadata["unused_days"] != float64(2) || u.Metadata["stale"] != false || u.RiskScore != 30 ||
		u.Ref != "aws-iam:m3-ci-deployer:m3l1-key-used" || u.Fingerprint != "aws-iam:m3l1-key-used" {
		t.Fatalf("the used key today = %+v", u)
	}
	if n := today["m3l1-key-never"]; n.Metadata["never_used"] != true || n.Metadata["last_used_at"] != nil || n.Metadata["stale"] != false || n.Metadata["created_at"] == nil || n.Metadata["last_use_unknown"] != nil {
		t.Fatalf("the never-used key today = %+v", n)
	}
	if off := today["m3l1-key-off"]; off.Metadata["status"] != "Inactive" || off.Metadata["stale"] != false || off.RiskScore != 30 {
		t.Fatalf("the inactive key today = %+v", off)
	}

	// 91 days on: both active keys are unused for 90 days; the inactive one is not flagged.
	dispatcher := h.srv.obHandler.(*issuanceDispatcher)
	dispatcher.accessKeyNow = func() time.Time { return iam.now.Add(91 * 24 * time.Hour) }
	defer func() { dispatcher.accessKeyNow = nil }()
	aged := runAt("m3l1-aws-91-days")
	for _, id := range []string{"m3l1-key-used", "m3l1-key-never"} {
		if f := aged[id]; f.Metadata["stale"] != true || f.RiskScore != 80 || f.Metadata["unused_days"].(float64) < 90 {
			t.Fatalf("an active key unused for 90 days is not flagged: %+v", f)
		}
	}
	if off := aged["m3l1-key-off"]; off.Metadata["stale"] != false || off.RiskScore != 30 {
		t.Fatalf("the inactive key is flagged: %+v", off)
	}

	iam.mu.Lock()
	defer iam.mu.Unlock()
	if len(iam.seen) == 0 {
		t.Fatal("the stand-in saw no request")
	}
	for _, req := range iam.seen {
		if strings.Contains(req, signingSecret) {
			t.Fatal("the secret access key travelled in a request")
		}
	}
}

// M3-L3 Done-when (served): after an aws-iam cloud access key discovery run
// against the IAM stand-in (ListUsers reports each user's ARN, as IAM's
// documented response carries it), the graph links each discovered key to
// its IAM user: key GRANTS_ACCESS res:aws_iam_user:<ARN>, so whoever holds
// the key is shown acting as that user.
func TestServedCloudAccessKeyActsAsItsIAMUserInTheGraphM3L3(t *testing.T) {
	iam := &m3l1IAMStandIn{now: time.Now().UTC()}
	srv := httptest.NewServer(iam)
	t.Cleanup(srv.Close)
	const signingSecret = "m3l3-standin-signing-value"        // #nosec G101 -- the test's own stand-in signing value, not a credential (CWE-798)
	t.Setenv("TRSTCTL_M3L3_IAM_ACCESS_KEY_ID", "m3l1-reader") // the stand-in admits this access key ID
	t.Setenv("TRSTCTL_M3L3_IAM_SECRET_ACCESS_KEY", signingSecret)
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs(
		"env:TRSTCTL_M3L3_IAM_ACCESS_KEY_ID", "env:TRSTCTL_M3L3_IAM_SECRET_ACCESS_KEY"))
	ctx := t.Context()
	writer := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "graph:read", string(authz.PrivateEgress))
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", writer, map[string]any{
		"name": "aws-iam-keys-graph", "kind": "cloud_access_key", "config": map[string]any{"providers": []map[string]any{{ // #nosec G101 -- credential references only; no credential value enters the config (CWE-798)
			"provider": "aws-iam", "endpoint": srv.URL, "allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, srv.URL)},
			"access_key_id_ref": "env:TRSTCTL_M3L3_IAM_ACCESS_KEY_ID", "secret_access_key_ref": "env:TRSTCTL_M3L3_IAM_SECRET_ACCESS_KEY",
		}}},
	})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil || source.ID == "" {
		t.Fatalf("create the source: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/runs", writer, "m3l3-run", map[string]any{"source_id": source.ID})
	if status != http.StatusCreated {
		t.Fatalf("queue the run: %d %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/graph", writer, nil)
	var g struct {
		Nodes []struct {
			ID    string            `json:"id"`
			Attrs map[string]string `json:"attrs"`
		} `json:"nodes"`
		Edges []struct {
			From string `json:"from"`
			To   string `json:"to"`
			Type string `json:"type"`
		} `json:"edges"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &g) != nil {
		t.Fatalf("graph: %d %s", status, body)
	}
	keyNodes := map[string]string{} // discovery ref -> node id
	for _, n := range g.Nodes {
		if n.Attrs["credential_kind"] == "cloud_access_key" {
			keyNodes[n.Attrs["discovery_ref"]] = n.ID
		}
	}
	edges := map[string]bool{}
	for _, e := range g.Edges {
		edges[e.From+" "+e.Type+" "+e.To] = true
	}
	for ref, arn := range map[string]string{
		"aws-iam:m3-ci-deployer:m3l1-key-used": "arn:aws:iam::123456789012:user/ci/m3-ci-deployer",
		"aws-iam:m3-backup-job:m3l1-key-never": "arn:aws:iam::123456789012:user/m3-backup-job",
		"aws-iam:m3-backup-job:m3l1-key-off":   "arn:aws:iam::123456789012:user/m3-backup-job",
	} {
		node, ok := keyNodes[ref]
		if !ok {
			t.Fatalf("no graph node for the key %s: %s", ref, body)
		}
		if want := node + " GRANTS_ACCESS res:aws_iam_user:" + arn; !edges[want] {
			t.Fatalf("missing %q", want)
		}
	}
	t.Logf("M3L3_KEY_PRINCIPAL_OK keys=%d", len(keyNodes))
}
