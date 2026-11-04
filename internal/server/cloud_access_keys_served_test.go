// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
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
