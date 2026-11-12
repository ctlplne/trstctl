// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
)

// m3l1GCPStandIn is Google IAM and Policy Analyzer for project "p": one
// service account with a recently used key, an idle key, a never-used key and
// a disabled account's key.
func m3l1GCPStandIn(t *testing.T, denyActivity *atomic.Bool) *httptest.Server {
	t.Helper()
	now := time.Now().UTC()
	day := func(d int) string { return now.AddDate(0, 0, d).Format(time.RFC3339) }
	key := func(account, id, created string) map[string]any {
		return map[string]any{"name": "projects/p/serviceAccounts/" + account + "/keys/" + id, "validAfterTime": created, "validBeforeTime": "9999-12-31T23:59:59Z"}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer m3l1-read-token" {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/v1/projects/p/serviceAccounts":
			_ = json.NewEncoder(w).Encode(map[string]any{"accounts": []any{
				map[string]any{"email": "deploy@p.iam.gserviceaccount.com"},
				map[string]any{"email": "retired@p.iam.gserviceaccount.com", "disabled": true},
			}})
		case r.URL.Path == "/v1/projects/p/serviceAccounts/deploy@p.iam.gserviceaccount.com/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{
				key("deploy@p.iam.gserviceaccount.com", "k-used", day(-300)),
				key("deploy@p.iam.gserviceaccount.com", "k-idle", day(-300)),
				key("deploy@p.iam.gserviceaccount.com", "k-never", day(-120)),
			}})
		case r.URL.Path == "/v1/projects/p/serviceAccounts/retired@p.iam.gserviceaccount.com/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{key("retired@p.iam.gserviceaccount.com", "k-off", day(-400))}})
		case strings.HasSuffix(r.URL.Path, "/activityTypes/serviceAccountKeyLastAuthentication/activities:query"):
			if denyActivity.Load() {
				http.Error(w, "permission denied", http.StatusForbidden)
				return
			}
			res := "//iam.googleapis.com/projects/p/serviceAccounts/deploy@p.iam.gserviceaccount.com/keys/"
			_ = json.NewEncoder(w).Encode(map[string]any{"activities": []any{
				map[string]any{"fullResourceName": res + "k-used", "activity": map[string]any{"lastAuthenticatedTime": day(-2)}},
				map[string]any{"fullResourceName": res + "k-idle", "activity": map[string]any{"lastAuthenticatedTime": day(-100)}},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestServedCloudAccessKeyDiscoveryReadsGCPServiceAccountKeysM3L1 is M3-L1: a
// cloud_access_key source with a gcp-iam provider reads a project's
// user-managed service-account keys with their age and last authentication
// from Policy Analyzer; an active key that has not authenticated for 90 days
// (or never did, 120 days after creation) is stale with risk 80, a recently
// used key and a disabled account's key are not. When Policy Analyzer cannot
// be read, the keys are still recorded with their last use unknown, none is
// called stale, and the run is partial with the reason. No token reaches a
// finding.
func TestServedCloudAccessKeyDiscoveryReadsGCPServiceAccountKeysM3L1(t *testing.T) {
	var deny atomic.Bool
	gcp := m3l1GCPStandIn(t, &deny)
	t.Setenv("TRSTCTL_M3L1_GCP_TOKEN", "m3l1-read-token")
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs("env:TRSTCTL_M3L1_GCP_TOKEN"))
	ctx := t.Context()
	writer := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "nhi:read", string(authz.PrivateEgress))
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", writer, map[string]any{
		"name": "gcp-sa-keys", "kind": "cloud_access_key", "config": map[string]any{"providers": []map[string]any{{ // #nosec G101 -- a credential reference only; no credential value enters the config (CWE-798)
			"provider": "gcp-iam", "project": "p", "endpoint": gcp.URL, "activity_endpoint": gcp.URL,
			"allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, gcp.URL)},
			"token_ref": "env:TRSTCTL_M3L1_GCP_TOKEN",
		}}},
	})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil || source.ID == "" {
		t.Fatalf("create the gcp-iam cloud_access_key source: %d %s", status, body)
	}
	type finding struct {
		Ref         string         `json:"ref"`
		Fingerprint string         `json:"fingerprint"`
		RiskScore   int            `json:"risk_score"`
		Metadata    map[string]any `json:"metadata"`
	}
	run := func(key string) (map[string]any, map[string]finding) {
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
		if status != http.StatusOK || json.Unmarshal(body, &listed) != nil || bytes.Contains(body, []byte("m3l1-read-token")) {
			t.Fatalf("findings of %s: %d %s", key, status, body)
		}
		byKey := map[string]finding{}
		for _, f := range listed.Items {
			byKey[f.Metadata["access_key_id"].(string)] = f
		}
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, writer, nil)
		var runState map[string]any
		if status != http.StatusOK || json.Unmarshal(body, &runState) != nil {
			t.Fatalf("run %s: %d %s", key, status, body)
		}
		return runState, byKey
	}

	state, keys := run("m3l1-1")
	if state["status"] != "succeeded" || len(keys) != 4 {
		t.Fatalf("run = %v, %d keys %v", state["status"], len(keys), keys)
	}
	for id, want := range map[string]struct {
		status string
		stale  bool
		risk   int
	}{
		"k-used": {"Active", false, 30}, "k-idle": {"Active", true, 80}, "k-never": {"Active", true, 80}, "k-off": {"Disabled", false, 30},
	} {
		f := keys[id]
		if f.Metadata["provider"] != "gcp-iam" || f.Metadata["status"] != want.status || f.Metadata["stale"] != want.stale || f.RiskScore != want.risk ||
			f.Fingerprint != "gcp-iam:"+id || f.Metadata["project"] != "p" {
			t.Errorf("%s = %+v; want %s, stale %v, risk %d", id, f, want.status, want.stale, want.risk)
		}
	}
	if keys["k-used"].Metadata["last_used_at"] == nil || keys["k-never"].Metadata["never_used"] != true ||
		keys["k-used"].Metadata["user"] != "deploy@p.iam.gserviceaccount.com" {
		t.Fatalf("last use = %v / %v", keys["k-used"].Metadata, keys["k-never"].Metadata)
	}

	// Policy Analyzer refused: recorded with last use unknown, nothing stale, run partial.
	deny.Store(true)
	state, keys = run("m3l1-2")
	if reason, _ := state["error"].(string); state["status"] != "partial" || !strings.Contains(reason, "last use could not be read") || len(keys) != 4 {
		t.Fatalf("run with the activity refused = %v; %d keys", state, len(keys))
	}
	for id, f := range keys {
		if f.Metadata["last_use_unknown"] != true || f.Metadata["stale"] != false || f.Metadata["never_used"] != nil {
			t.Fatalf("%s with last use unknown = %+v", id, f.Metadata)
		}
	}
}
