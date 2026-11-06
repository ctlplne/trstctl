// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"encoding/json"
	googleuuid "github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/cloudentitlements/gcpiam"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/projections"
)

// Native API-shaped fixtures exercise the served collector, not a live GCP account.
func TestServedGCPMachineIdentityInventoryA264(t *testing.T) {
	authority := []byte("owned-gcp-inventory-authority")
	defer secret.Wipe(authority)
	var calls atomic.Int32
	var denyRole, wrongIdentity atomic.Bool
	now := time.Now().UTC().Truncate(time.Second)
	native := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !bytes.Equal([]byte(r.Header.Get("Authorization")), append([]byte("Bearer "), authority...)) {
			w.WriteHeader(401)
			return
		}
		if r.URL.Query().Get("fields") == "" {
			t.Error("collector omitted the public-metadata response mask")
			w.WriteHeader(400)
			return
		}
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		var reply any
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/projects/owned-project/serviceAccounts/orders@owned-project.iam.gserviceaccount.com":
			if wrongIdentity.Load() {
				_ = json.NewEncoder(w).Encode(map[string]any{"name": "projects/owned-project/serviceAccounts/other@owned-project.iam.gserviceaccount.com", "projectId": "owned-project", "uniqueId": "999999999999999999999", "email": "other@owned-project.iam.gserviceaccount.com"})
				return
			}
			reply = map[string]any{"name": "projects/owned-project/serviceAccounts/orders@owned-project.iam.gserviceaccount.com", "projectId": "owned-project", "uniqueId": "123456789012345678901", "email": "orders@owned-project.iam.gserviceaccount.com", "displayName": "Orders worker", "disabled": false}
		case "GET /v1/projects/owned-project/serviceAccounts/orders@owned-project.iam.gserviceaccount.com/keys":
			reply = map[string]any{"keys": []any{map[string]any{"name": "projects/owned-project/serviceAccounts/orders@owned-project.iam.gserviceaccount.com/keys/0123456789abcdef0123456789abcdef01234567", "keyType": "USER_MANAGED", "keyOrigin": "GOOGLE_PROVIDED", "validAfterTime": now.Add(-400 * 24 * time.Hour), "validBeforeTime": now.Add(24 * time.Hour), "disabled": false}}}
		case "POST /v1/projects/owned-project/serviceAccounts/orders@owned-project.iam.gserviceaccount.com:getIamPolicy":
			reply = map[string]any{"version": 3, "etag": "owned-trust-version", "bindings": []any{map[string]any{"role": "roles/iam.workloadIdentityUser", "members": []string{"principalSet://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/owned/attribute.repository/owned/orders"}}}}
		case "POST /v1/projects/owned-project:getIamPolicy":
			reply = map[string]any{"version": 3, "etag": "owned-project-policy-version", "bindings": []any{map[string]any{"role": "roles/storage.objectViewer", "members": []string{"serviceAccount:orders@owned-project.iam.gserviceaccount.com"}, "condition": map[string]any{"title": "Owned bucket", "expression": "resource.name.startsWith('projects/_/buckets/owned-orders/')"}}}}
		case "GET /v1/roles/storage.objectViewer":
			if denyRole.Load() {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			reply = map[string]any{"name": "roles/storage.objectViewer", "title": "Storage Object Viewer", "stage": "GA", "includedPermissions": []string{"storage.objects.get", "storage.objects.list"}}
		case "POST /v2/entries:list":
			reply = map[string]any{"entries": []any{map[string]any{"timestamp": now.Add(-time.Hour), "protoPayload": map[string]any{"authenticationInfo": map[string]any{"principalEmail": "orders@owned-project.iam.gserviceaccount.com", "serviceAccountKeyName": "//iam.googleapis.com/projects/owned-project/serviceAccounts/orders@owned-project.iam.gserviceaccount.com/keys/0123456789abcdef0123456789abcdef01234567"}, "status": map[string]any{"code": 0}}}}}
		default:
			t.Errorf("collector used an unimplemented native read: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(400)
			return
		}
		_ = json.NewEncoder(w).Encode(reply)
	}))
	defer native.Close()
	path := filepath.Join(t.TempDir(), "reader")
	if err := os.WriteFile(path, authority, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRSTCTL_A264_GCP_READER_PATH", path)
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs("env:TRSTCTL_A264_GCP_READER_PATH"))
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "gcp-inventory-operator", "discovery:read", "discovery:write", "graph:read", "nhi:read", string(authz.PrivateEgress))
	cfg := map[string]any{"project": "owned-project", "service_accounts": []string{"orders@owned-project.iam.gserviceaccount.com"}, "token_file_ref": strings.Join([]string{"env", "TRSTCTL_A264_GCP_READER_PATH"}, ":"), "iam_endpoint": native.URL, "resource_manager_endpoint": native.URL, "logging_endpoint": native.URL, "activity_lookback_days": 30, "allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, native.URL)}}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", operator, "a264-gcp-inventory-source", map[string]any{"kind": "gcp_machine_identity", "name": "Owned GCP workload inventory", "config": cfg})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil || source.ID == "" {
		t.Fatalf("GCP workload inventory source unavailable: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/runs", operator, "a264-gcp-inventory-run", map[string]any{"source_id": source.ID})
	var run struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &run) != nil {
		t.Fatal("GCP inventory run unavailable")
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+run.ID, operator, nil)
	var findings struct {
		Items []struct {
			Kind     string          `json:"kind"`
			Metadata json.RawMessage `json:"metadata"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &findings) != nil || len(findings.Items) != 1 {
		t.Fatalf("GCP inventory findings unavailable: %d %s", status, body)
	}
	if calls.Load() < 6 || !bytes.Contains(findings.Items[0].Metadata, []byte("123456789012345678901")) || !bytes.Contains(findings.Items[0].Metadata, []byte("storage.objects.get")) || !bytes.Contains(findings.Items[0].Metadata, []byte("0123456789abcdef0123456789abcdef01234567")) || !bytes.Contains(findings.Items[0].Metadata, []byte("observed_only")) || bytes.Contains(body, authority) {
		t.Fatal("GCP native identity/policy/key/activity evidence incomplete or credential leaked")
	}

	inventory, err := gcpiam.DecodeInventory(findings.Items[0].Metadata)
	if err != nil || len(inventory.Keys) != 1 || inventory.Keys[0].LastObservedUse == nil || !inventory.Keys[0].LastObservedUse.Equal(now.Add(-time.Hour)) || !inventory.Keys[0].LongLived || len(inventory.PolicyBindings) != 1 || inventory.PolicyBindings[0].Condition == nil || inventory.PolicyBindings[0].PermissionCoverage != "role_definition_only" {
		t.Fatal("GCP key-use, age or conditional role metadata was not retained exactly")
	}
	status, graphBody := secretsReq(t, h, http.MethodGet, "/api/v1/graph", operator, nil)
	if status != http.StatusOK || !bytes.Contains(graphBody, []byte("gcp-key:")) || !bytes.Contains(graphBody, []byte("effective access is unknown")) {
		t.Fatal("GCP graph lost native ownership or invented effective access")
	}

	var graphEdges struct {
		Edges []struct {
			From string `json:"from"`
			Type string `json:"type"`
		} `json:"edges"`
	}
	if json.Unmarshal(graphBody, &graphEdges) != nil {
		t.Fatal("GCP graph edges unreadable")
	}
	for _, edge := range graphEdges.Edges {
		if strings.HasPrefix(edge.From, "gcp-") && edge.Type == "GRANTS_ACCESS" {
			t.Fatal("partial GCP bindings manufactured an effective-access edge")
		}
	}
	status, nhiBody := secretsReq(t, h, http.MethodGet, "/api/v1/nhi/inventory", operator, nil)
	if status != http.StatusOK || !bytes.Contains(nhiBody, []byte(`"kind":"service_account"`)) || bytes.Contains(nhiBody, authority) {
		t.Fatal("GCP NHI classification or credential privacy failed")
	}
	otherTenant := googleuuid.NewString()
	registerServedTenantID(t, h, otherTenant, "GCP inventory isolation tenant")
	other := seedScopedToken(t, h.store, otherTenant, "discovery:read", "graph:read", "nhi:read")
	for _, path := range []string{"/api/v1/discovery/findings?run_id=" + run.ID, "/api/v1/graph", "/api/v1/nhi/inventory"} {
		status, foreign := secretsReq(t, h, http.MethodGet, path, other, nil)
		if status != http.StatusOK || bytes.Contains(foreign, []byte("owned-project")) {
			t.Fatal("foreign tenant read GCP workload evidence")
		}
	}
	projector := projections.New(h.store)
	if err := projector.ProjectCatchUp(t.Context(), h.log); err != nil {
		t.Fatal(err)
	}
	if _, err := projector.Snapshot(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := projector.Rebuild(t.Context(), h.log); err != nil {
		t.Fatal(err)
	}
	status, replayed := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+run.ID, operator, nil)
	if status != http.StatusOK || !bytes.Equal(body, replayed) {
		t.Fatal("GCP native inventory changed after snapshot/rebuild")
	}

	denyRole.Store(true)
	status, queued := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/runs", operator, "a264-gcp-partial-role", map[string]any{"source_id": source.ID})
	var partialRun struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(queued, &partialRun) != nil {
		t.Fatal("partial capture enqueue unavailable")
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	partial, err := h.store.GetDiscoveryRun(t.Context(), h.tenant, partialRun.ID)
	if err != nil || partial.Status != "partial" || partial.Discovered != 1 {
		t.Fatal("missing role permission was reported as complete inventory")
	}
	wrongIdentity.Store(true)
	status, queued = secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/runs", operator, "a264-gcp-foreign-identity", map[string]any{"source_id": source.ID})
	var failedRun struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(queued, &failedRun) != nil {
		t.Fatal("identity mismatch capture enqueue unavailable")
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	failed, err := h.store.GetDiscoveryRun(t.Context(), h.tenant, failedRun.ID)
	if err != nil || failed.Status != "failed" || failed.Discovered != 0 {
		t.Fatal("a different native account was accepted as the selected workload")
	}

}
