// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
)

// m3l2GraphStandIn is Microsoft Graph for one tenant: an application with a
// recently used secret and an idle one, and another with a never-used secret
// and an expired one.
func m3l2GraphStandIn(t *testing.T, denyActivity *atomic.Bool) *httptest.Server {
	t.Helper()
	now := time.Now().UTC()
	day := func(d int) string { return now.AddDate(0, 0, d).Format(time.RFC3339) }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer m3l2-graph-token" {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1.0/applications":
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{
				map[string]any{"id": "o1", "appId": "a1", "displayName": "payments-api", "passwordCredentials": []any{
					map[string]any{"keyId": "s-used", "displayName": "ci", "hint": "Zq7", "startDateTime": day(-200), "endDateTime": day(500)},
					map[string]any{"keyId": "s-idle", "displayName": "old ci", "hint": "Xy1", "startDateTime": day(-300), "endDateTime": day(300)},
				}},
				map[string]any{"id": "o2", "appId": "a2", "displayName": "batch-job", "passwordCredentials": []any{
					map[string]any{"keyId": "s-never", "displayName": "batch", "startDateTime": day(-120), "endDateTime": day(240)},
					map[string]any{"keyId": "s-expired", "displayName": "expired", "startDateTime": day(-800), "endDateTime": day(-5)},
				}},
			}})
		case "/beta/reports/appCredentialSignInActivities":
			if denyActivity.Load() {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{
				map[string]any{"keyId": "s-used", "signInActivity": map[string]any{"lastSignInDateTime": day(-4)}},
				map[string]any{"keyId": "s-idle", "signInActivity": map[string]any{"lastSignInDateTime": day(-140)}},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestServedCloudAccessKeyDiscoveryReadsAzureAppSecretsM3L2 is M3-L2: a
// cloud_access_key source with an azure-entra provider reads a tenant's
// app-registration client secrets with their creation, expiry and last
// sign-in; an active secret that has not signed in for 90 days (or never did,
// 120 days after creation) is stale with risk 80, a recently used and an
// expired secret are not. No token, and no secret hint, reaches a finding.
// When the sign-in activity cannot be read, the secrets are recorded with
// their last use unknown and the run is partial.
func TestServedCloudAccessKeyDiscoveryReadsAzureAppSecretsM3L2(t *testing.T) {
	var deny atomic.Bool
	graph := m3l2GraphStandIn(t, &deny)
	t.Setenv("TRSTCTL_M3L2_GRAPH_TOKEN", "m3l2-graph-token")
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs("env:TRSTCTL_M3L2_GRAPH_TOKEN"))
	ctx := t.Context()
	writer := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "nhi:read", string(authz.PrivateEgress))
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", writer, map[string]any{
		"name": "entra-app-secrets", "kind": "cloud_access_key", "config": map[string]any{"providers": []map[string]any{{ // #nosec G101 -- a credential reference only; no credential value enters the config (CWE-798)
			"provider": "azure-entra", "endpoint": graph.URL,
			"allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, graph.URL)},
			"token_ref": "env:TRSTCTL_M3L2_GRAPH_TOKEN",
		}}},
	})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil || source.ID == "" {
		t.Fatalf("create the azure-entra cloud_access_key source: %d %s", status, body)
	}
	type finding struct {
		Fingerprint string         `json:"fingerprint"`
		RiskScore   int            `json:"risk_score"`
		Metadata    map[string]any `json:"metadata"`
	}
	run := func(key string) (string, map[string]finding) {
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
		for _, leaked := range []string{"m3l2-graph-token", "Zq7", "Xy1"} {
			if bytes.Contains(body, []byte(leaked)) {
				t.Fatalf("%q reached the findings API", leaked)
			}
		}
		byKey := map[string]finding{}
		for _, f := range listed.Items {
			byKey[f.Metadata["access_key_id"].(string)] = f
		}
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, writer, nil)
		var runState struct {
			Status string `json:"status"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &runState) != nil {
			t.Fatalf("run %s: %d %s", key, status, body)
		}
		return runState.Status, byKey
	}

	state, secrets := run("m3l2-1")
	if state != "succeeded" || len(secrets) != 4 {
		t.Fatalf("run = %s, %d secrets", state, len(secrets))
	}
	for id, want := range map[string]struct {
		app, status string
		stale       bool
		risk        int
	}{
		"s-used": {"payments-api", "Active", false, 30}, "s-idle": {"payments-api", "Active", true, 80},
		"s-never": {"batch-job", "Active", true, 80}, "s-expired": {"batch-job", "Expired", false, 30},
	} {
		f := secrets[id]
		if f.Metadata["provider"] != "azure-entra" || f.Metadata["user"] != want.app || f.Metadata["status"] != want.status ||
			f.Metadata["stale"] != want.stale || f.RiskScore != want.risk || f.Fingerprint != "azure-entra:"+id || f.Metadata["expires_at"] == nil {
			t.Errorf("%s = %+v; want %s %s, stale %v, risk %d", id, f, want.app, want.status, want.stale, want.risk)
		}
	}
	if secrets["s-used"].Metadata["last_used_at"] == nil || secrets["s-never"].Metadata["never_used"] != true || secrets["s-used"].Metadata["app_id"] != "a1" {
		t.Fatalf("last use = %v / %v", secrets["s-used"].Metadata, secrets["s-never"].Metadata)
	}

	deny.Store(true)
	state, secrets = run("m3l2-2")
	if state != "partial" || len(secrets) != 4 {
		t.Fatalf("run with the sign-in activity refused = %s, %d secrets", state, len(secrets))
	}
	for id, f := range secrets {
		if f.Metadata["last_use_unknown"] != true || f.Metadata["stale"] != false {
			t.Fatalf("%s with last use unknown = %+v", id, f.Metadata)
		}
	}
}
