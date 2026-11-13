// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
)

// TestServedStaleCloudKeyIsReplacedByADynamicRoleM3L4 is M3-L4 on an IAM
// stand-in. Discovery records a key last used 120 days ago as stale; the
// operator replaces it from the finding with an AWS STS dynamic-secret role;
// trstctl sets the key Inactive at IAM through the source's own connection
// (a signed UpdateAccessKey, never a deletion) and the finding is remediated
// with the role as its evidence. IAM failing on its side leaves the request
// queued until it answers. The route refuses a caller without
// connectors:write, a provider that is not AWS STS or does not exist, a role
// the provider does not allow, and a key that is no longer Active; a key IAM
// no longer has is recorded already absent and the finding still remediated.
func TestServedStaleCloudKeyIsReplacedByADynamicRoleM3L4(t *testing.T) {
	iam := newM3L4IAMStandIn(time.Now().UTC())
	srv := httptest.NewServer(iam)
	t.Cleanup(srv.Close)
	const signingValue = "m3l4-standin-signing-value" // #nosec G101 -- the test's own stand-in signing value, not a credential (CWE-798)
	t.Setenv("TRSTCTL_M3L4_IAM_ACCESS_KEY_ID", "m3l4-operator")
	t.Setenv("TRSTCTL_M3L4_IAM_SECRET_ACCESS_KEY", signingValue)
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs(
		"env:TRSTCTL_M3L4_IAM_ACCESS_KEY_ID", "env:TRSTCTL_M3L4_IAM_SECRET_ACCESS_KEY"), func(d *Deps) {
		d.EnableSecretsAPI = true
		resolver := integrationCredentialResolver{store: d.Store, kek: d.KEK, crypto: d.TenantCrypto}
		sts := config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: "m3l4-aws", Type: "aws-sts", Endpoint: srv.URL, IAMEndpoint: srv.URL,
			AllowInsecureLoopback: true, Region: "us-east-1", AccessKeyID: "m3l4-sts",
			SecretAccessRef: writeServedCredentialFile(t, "m3l4-sts-value", "m3l4-sts-signing"),
			AllowedRoles:    []string{"build"}, RoleBindings: map[string]string{"build": "arn:aws:iam::123456789012:role/m3l4-build"}, MaxTTL: "1h",
		}
		pg := config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: "m3l4-pg", Type: "postgresql", AdminDSNRef: writeServedCredentialFile(t, "m3l4-pg-dsn", "postgres://127.0.0.1:1/none"),
			Database: "postgres", Schema: "public", UsernamePrefix: "trstctl", AllowedRoles: []string{"build"}, MaxTTL: time.Hour.String(),
		}
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {
			newConfiguredDynamicProvider(sts, map[string]bool{"build": true}, time.Hour, resolver, nil),
			newConfiguredDynamicProvider(pg, map[string]bool{"build": true}, time.Hour, resolver, nil),
		}}
	})
	ctx := t.Context()
	operator := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "connectors:write", "secrets:read", string(authz.PrivateEgress))
	reader := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "secrets:read")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/discovery/sources", operator, map[string]any{
		"name": "m3l4-aws-keys", "kind": "cloud_access_key", "config": map[string]any{"providers": []map[string]any{{ // #nosec G101 -- credential references only; no credential value enters the config (CWE-798)
			"provider": "aws-iam", "endpoint": srv.URL, "allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, srv.URL)},
			"access_key_id_ref": "env:TRSTCTL_M3L4_IAM_ACCESS_KEY_ID", "secret_access_key_ref": "env:TRSTCTL_M3L4_IAM_SECRET_ACCESS_KEY",
		}}},
	})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil || source.ID == "" {
		t.Fatalf("create the aws-iam cloud_access_key source: %d %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodPost, "/api/v1/discovery/runs", operator, map[string]any{"source_id": source.ID})
	var run struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &run) != nil {
		t.Fatalf("run the source: %d %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain the run: %v", err)
	}
	type findingRow struct {
		ID           string         `json:"id"`
		TriageStatus string         `json:"triage_status"`
		TriageReason string         `json:"triage_reason"`
		Metadata     map[string]any `json:"metadata"`
	}
	read := func(query string) []findingRow {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?"+query, operator, nil)
		var list struct {
			Items []findingRow `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &list) != nil {
			t.Fatalf("findings %s: %d %s", query, status, body)
		}
		return list.Items
	}
	byKey := map[string]findingRow{}
	for _, f := range read("kind=cloud_access_key&limit=100&run_id=" + run.ID) {
		byKey[fmt.Sprint(f.Metadata["access_key_id"])] = f
	}
	stale, fresh := byKey["m3l4-key-stale"], byKey["m3l4-key-fresh"]
	if len(byKey) != 2 || stale.Metadata["stale"] != true || fresh.Metadata["stale"] == true {
		t.Fatalf("discovered keys = %+v; want the stale key and the fresh one", byKey)
	}
	replace := func(findingID, token, key string, req map[string]any) (int, []byte) {
		t.Helper()
		return secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/findings/"+findingID+"/cloud-key/replace", token, key, req)
	}
	for name, c := range map[string]struct {
		token string
		req   map[string]any
		want  int
	}{
		"no connectors:write":     {reader, map[string]any{"provider": "m3l4-aws", "role": "build"}, http.StatusForbidden},
		"not an AWS provider":     {operator, map[string]any{"provider": "m3l4-pg", "role": "build"}, http.StatusUnprocessableEntity},
		"no such provider":        {operator, map[string]any{"provider": "m3l4-none", "role": "build"}, http.StatusUnprocessableEntity},
		"a role it doesn't allow": {operator, map[string]any{"provider": "m3l4-aws", "role": "admin"}, http.StatusUnprocessableEntity},
		"no role":                 {operator, map[string]any{"provider": "m3l4-aws"}, http.StatusBadRequest},
	} {
		if status, body := replace(stale.ID, c.token, "m3l4-refused-"+strings.ReplaceAll(name, " ", "-"), c.req); status != c.want {
			t.Fatalf("%s: replace = %d %s; want %d", name, status, body, c.want)
		}
	}
	if n := iam.updateCount(); n != 0 {
		t.Fatalf("refused requests reached IAM %d times", n)
	}

	// IAM answers 503 until it recovers: the request stays queued and is
	// retried (however often a slow drain retries it before then).
	iam.failNext(1000)
	status, body = replace(stale.ID, operator, "m3l4-replace-stale", map[string]any{"provider": "m3l4-aws", "role": "build", "reason": "stale since spring"})
	var queued struct {
		RequestID   string `json:"request_id"`
		Action      string `json:"action"`
		AccessKeyID string `json:"access_key_id"`
		Replacement string `json:"replacement"`
		Status      string `json:"status"`
	}
	if status != http.StatusAccepted || json.Unmarshal(body, &queued) != nil || queued.Action != "deactivate_key" ||
		queued.AccessKeyID != "m3l4-key-stale" || queued.Replacement != "dynamic-secret:m3l4-aws/build" || queued.Status != "queued" {
		t.Fatalf("replace the stale key = %d %s", status, body)
	}
	if status, again := replace(stale.ID, operator, "m3l4-replace-stale", map[string]any{"provider": "m3l4-aws", "role": "build", "reason": "stale since spring"}); status != http.StatusAccepted || string(again) != string(body) {
		t.Fatalf("the retried request = %d %s; want the same answer %s", status, again, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain the first attempt: %v", err)
	}
	action := func(f findingRow) map[string]any {
		actions, _ := f.Metadata["provider_actions"].(map[string]any)
		out, _ := actions["deactivate_key"].(map[string]any)
		return out
	}
	if got := read("id=" + stale.ID); len(got) != 1 || action(got[0])["status"] != "queued" || iam.statusOf("m3l4-key-stale") != "Active" {
		t.Fatalf("after IAM's 503 = %+v, IAM status %s; want still queued and the key Active", got, iam.statusOf("m3l4-key-stale"))
	}
	iam.failNext(0)
	forceCloudKeyActionDue(t, h, queued.RequestID)
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain the retry: %v", err)
	}
	got := read("id=" + stale.ID)
	if len(got) != 1 || action(got[0])["status"] != "confirmed" || got[0].TriageStatus != "remediated" ||
		got[0].Metadata["status"] != "Inactive" || got[0].Metadata["replaced_by"] != "dynamic-secret:m3l4-aws/build" ||
		!strings.Contains(got[0].TriageReason, "dynamic-secret:m3l4-aws/build") {
		t.Fatalf("the replaced key's finding = %+v", got)
	}
	if iam.statusOf("m3l4-key-stale") != "Inactive" || !iam.allSigned() || iam.updateCount() != 1 {
		t.Fatalf("IAM status %s, signed %v, updates %d; want Inactive through one signed UpdateAccessKey",
			iam.statusOf("m3l4-key-stale"), iam.allSigned(), iam.updateCount())
	}
	if status, body := replace(stale.ID, operator, "m3l4-replace-again", map[string]any{"provider": "m3l4-aws", "role": "build"}); status != http.StatusConflict {
		t.Fatalf("replacing an Inactive key = %d %s; want 409", status, body)
	}

	// A key IAM no longer has: recorded already absent, still remediated.
	iam.forget("m3l4-key-fresh")
	if status, body := replace(fresh.ID, operator, "m3l4-replace-fresh", map[string]any{"provider": "m3l4-aws", "role": "build"}); status != http.StatusAccepted {
		t.Fatalf("replace the deleted key = %d %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain the deleted key: %v", err)
	}
	if got := read("id=" + fresh.ID); len(got) != 1 || action(got[0])["status"] != "already_absent" || got[0].TriageStatus != "remediated" {
		t.Fatalf("the deleted key's finding = %+v", got)
	}
	t.Logf("M3L4_CLOUD_KEY_REPLACED_OK request=%s replacement=%s updates=%d", queued.RequestID, queued.Replacement, iam.updateCount())
}

// forceCloudKeyActionDue makes a retried cloud key action row due now.
func forceCloudKeyActionDue(t *testing.T, h *servedHarness, requestID string) {
	t.Helper()
	err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(context.Background(), `
			UPDATE outbox
			SET status = 'pending', next_attempt_at = now(), worker_id = NULL, lease_until = NULL
			WHERE tenant_id = $1
			  AND destination = 'cloud_key.action'
			  AND idempotency_key = $2
		`, h.tenant, "cloud-key-action:"+requestID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("updated %d cloud_key.action rows for %q, want 1", tag.RowsAffected(), requestID)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("force the cloud key action due: %v", err)
	}
}

// m3l4IAMStandIn is AWS IAM's Query API as discovery reads it and a key
// replacement writes it (ListUsers, ListAccessKeys, GetAccessKeyLastUsed,
// UpdateAccessKey; version 2010-05-08), written from AWS's public API
// reference. One user's key was last used 120 days ago, another's yesterday.
// UpdateAccessKey sets a key's status and answers NoSuchEntity (404) for a
// key the named user does not hold; failNext makes the next calls answer 503.
type m3l4IAMStandIn struct {
	now      time.Time
	mu       sync.Mutex
	status   map[string]string
	owner    map[string]string
	updates  int
	unsigned int
	failures int
}

func newM3L4IAMStandIn(now time.Time) *m3l4IAMStandIn {
	return &m3l4IAMStandIn{now: now,
		status: map[string]string{"m3l4-key-stale": "Active", "m3l4-key-fresh": "Active"},
		owner:  map[string]string{"m3l4-key-stale": "m3l4-build-bot", "m3l4-key-fresh": "m3l4-reporter"}}
}

func (s *m3l4IAMStandIn) failNext(n int) { s.mu.Lock(); s.failures = n; s.mu.Unlock() }

func (s *m3l4IAMStandIn) forget(keyID string) {
	s.mu.Lock()
	delete(s.owner, keyID)
	delete(s.status, keyID)
	s.mu.Unlock()
}

func (s *m3l4IAMStandIn) statusOf(keyID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status[keyID]
}

func (s *m3l4IAMStandIn) updateCount() int { s.mu.Lock(); defer s.mu.Unlock(); return s.updates }

func (s *m3l4IAMStandIn) allSigned() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.unsigned == 0 }

func (s *m3l4IAMStandIn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(raw))
	signed := form.Get("Version") == "2010-05-08" && strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=m3l4-operator/")
	s.mu.Lock()
	defer s.mu.Unlock()
	if !signed {
		if form.Get("Action") == "UpdateAccessKey" {
			s.unsigned++
		}
		http.Error(w, "unsigned or wrong version", http.StatusForbidden)
		return
	}
	day := func(d int) string { return s.now.AddDate(0, 0, d).Format(time.RFC3339) }
	w.Header().Set("Content-Type", "text/xml")
	switch form.Get("Action") {
	case "ListUsers":
		_, _ = io.WriteString(w, `<ListUsersResponse><ListUsersResult><Users>`+
			`<member><UserName>m3l4-build-bot</UserName><Arn>arn:aws:iam::123456789012:user/m3l4-build-bot</Arn></member>`+
			`<member><UserName>m3l4-reporter</UserName><Arn>arn:aws:iam::123456789012:user/m3l4-reporter</Arn></member>`+
			`</Users><IsTruncated>false</IsTruncated></ListUsersResult></ListUsersResponse>`)
	case "ListAccessKeys":
		var keys string
		for id, user := range s.owner {
			if user != form.Get("UserName") {
				continue
			}
			created := day(-200)
			if id == "m3l4-key-fresh" {
				created = day(-30)
			}
			keys += "<member><UserName>" + user + "</UserName><AccessKeyId>" + id + "</AccessKeyId><Status>" + s.status[id] +
				"</Status><CreateDate>" + created + "</CreateDate></member>"
		}
		_, _ = io.WriteString(w, `<ListAccessKeysResponse><ListAccessKeysResult><AccessKeyMetadata>`+keys+`</AccessKeyMetadata><IsTruncated>false</IsTruncated></ListAccessKeysResult></ListAccessKeysResponse>`)
	case "GetAccessKeyLastUsed":
		used := day(-1)
		if form.Get("AccessKeyId") == "m3l4-key-stale" {
			used = day(-120)
		}
		_, _ = io.WriteString(w, `<GetAccessKeyLastUsedResponse><GetAccessKeyLastUsedResult><AccessKeyLastUsed><LastUsedDate>`+used+`</LastUsedDate><ServiceName>s3</ServiceName><Region>us-east-1</Region></AccessKeyLastUsed></GetAccessKeyLastUsedResult></GetAccessKeyLastUsedResponse>`)
	case "UpdateAccessKey":
		if s.failures > 0 {
			s.failures--
			http.Error(w, "ServiceFailure", http.StatusServiceUnavailable)
			return
		}
		id, next := form.Get("AccessKeyId"), form.Get("Status")
		if s.owner[id] == "" || s.owner[id] != form.Get("UserName") {
			http.Error(w, "NoSuchEntity", http.StatusNotFound)
			return
		}
		if next != "Active" && next != "Inactive" {
			http.Error(w, "ValidationError", http.StatusBadRequest)
			return
		}
		s.status[id] = next
		s.updates++
		_, _ = io.WriteString(w, `<UpdateAccessKeyResponse><ResponseMetadata><RequestId>m3l4-update</RequestId></ResponseMetadata></UpdateAccessKeyResponse>`)
	default:
		http.Error(w, "InvalidAction", http.StatusBadRequest)
	}
}
