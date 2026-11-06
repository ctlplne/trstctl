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
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/projections"
)

// Graph/ARM fixtures prove the served contract, never a live Azure deployment.
func TestServedAzureMachineIdentityInventoryA264(t *testing.T) {
	const tenant = "10000000-0000-0000-0000-000000000001"
	const subscription = "20000000-0000-0000-0000-000000000002"
	const principal = "30000000-0000-0000-0000-000000000003"
	const app = "40000000-0000-0000-0000-000000000004"
	const resource = "50000000-0000-0000-0000-000000000005"
	const role = "60000000-0000-0000-0000-000000000006"
	const key = "70000000-0000-0000-0000-000000000007"
	const roleDefinition = "/subscriptions/" + subscription + "/providers/Microsoft.Authorization/roleDefinitions/" + role
	graphAuthority, armAuthority := []byte("owned-graph-inventory-authority"), []byte("owned-arm-inventory-authority")
	defer secret.Wipe(graphAuthority)
	defer secret.Wipe(armAuthority)
	now := time.Now().UTC().Truncate(time.Second)
	var denyRole, wrongIdentity, managedIdentity, wrongTenant atomic.Bool
	var graphCalls, armCalls atomic.Int32
	graph := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !bytes.Equal([]byte(r.Header.Get("Authorization")), append([]byte("Bearer "), graphAuthority...)) {
			w.WriteHeader(401)
			return
		}
		graphCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		var reply any
		switch r.URL.Path {
		case "/v1.0/organization":
			nativeTenant := tenant
			if wrongTenant.Load() {
				nativeTenant = resource
			}
			reply = map[string]any{"value": []any{map[string]any{"id": nativeTenant}}}
		case "/v1.0/servicePrincipals/" + principal:
			id := principal
			if wrongIdentity.Load() {
				id = resource
			}
			reply = map[string]any{"id": id, "appId": app, "displayName": "Owned orders worker", "servicePrincipalType": "Application", "accountEnabled": true, "passwordCredentials": []any{map[string]any{"keyId": key, "startDateTime": now.Add(-400 * 24 * time.Hour), "endDateTime": now.Add(24 * time.Hour), "hint": "PRIVATE-CANARY-NOT-METADATA", "secretText": "PRIVATE-CANARY-NOT-METADATA"}}}
			if managedIdentity.Load() {
				reply = map[string]any{"id": id, "appId": app, "displayName": "Owned managed worker", "servicePrincipalType": "ManagedIdentity", "accountEnabled": true}
			}
		case "/v1.0/servicePrincipals/" + principal + "/appRoleAssignments":
			reply = map[string]any{"value": []any{map[string]any{"id": role, "principalId": principal, "resourceId": resource, "appRoleId": role}}}
		case "/v1.0/servicePrincipals/" + resource:
			reply = map[string]any{"id": resource, "appId": resource, "displayName": "Owned resource", "appRoles": []any{map[string]any{"id": role, "value": "Orders.Read", "allowedMemberTypes": []string{"Application"}, "isEnabled": true}}}
		case "/v1.0/applications(appId='" + app + "')/federatedIdentityCredentials":
			reply = map[string]any{"value": []any{map[string]any{"id": role, "name": "orders-federation", "issuer": "https://issuer.example.test", "subject": "system:serviceaccount:orders:worker", "audiences": []string{"api://AzureADTokenExchange"}}}}
		case "/beta/auditLogs/signIns":
			if !strings.Contains(r.URL.Query().Get("$filter"), "signInEventTypes/any") {
				t.Error("missing explicit workload sign-in filter")
			}
			reply = map[string]any{"value": []any{map[string]any{"createdDateTime": now.Add(-time.Hour), "servicePrincipalId": principal, "appId": app, "servicePrincipalCredentialKeyId": key, "signInEventTypes": []string{"servicePrincipal"}, "status": map[string]any{"errorCode": 0}}}}
		default:
			t.Errorf("unexpected Graph read %s", r.URL.Path)
			w.WriteHeader(400)
			return
		}
		_ = json.NewEncoder(w).Encode(reply)
	}))
	defer graph.Close()
	arm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !bytes.Equal([]byte(r.Header.Get("Authorization")), append([]byte("Bearer "), armAuthority...)) {
			w.WriteHeader(401)
			return
		}
		armCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		var reply any
		switch r.URL.Path {
		case "/subscriptions/" + subscription:
			reply = map[string]any{"subscriptionId": subscription, "tenantId": tenant}
		case "/subscriptions/" + subscription + "/providers/Microsoft.Authorization/roleAssignments":
			if r.URL.Query().Get("$filter") != "principalId eq '"+principal+"'" {
				t.Error("RBAC principal filter lost")
			}
			reply = map[string]any{"value": []any{map[string]any{"id": "/subscriptions/" + subscription + "/providers/Microsoft.Authorization/roleAssignments/" + role, "properties": map[string]any{"principalId": principal, "roleDefinitionId": roleDefinition, "scope": "/subscriptions/" + subscription, "condition": "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] StringEquals 'orders'", "conditionVersion": "2.0"}}}}
		case "/subscriptions/" + subscription + "/resourceGroups/owned/providers/Microsoft.ManagedIdentity/userAssignedIdentities/worker":
			reply = map[string]any{"id": r.URL.Path, "properties": map[string]any{"principalId": principal, "tenantId": tenant, "clientId": app}}
		case "/subscriptions/" + subscription + "/resourceGroups/owned/providers/Microsoft.ManagedIdentity/userAssignedIdentities/worker/federatedIdentityCredentials":
			reply = map[string]any{"value": []any{map[string]any{"id": strings.TrimSuffix(r.URL.Path, "/federatedIdentityCredentials") + "/federatedIdentityCredentials/owned", "name": "owned", "properties": map[string]any{"issuer": "https://issuer.example.test", "subject": "owned-worker", "audiences": []string{"api://AzureADTokenExchange"}}}}}
		case roleDefinition:
			if denyRole.Load() {
				w.WriteHeader(403)
				return
			}
			reply = map[string]any{"id": roleDefinition, "properties": map[string]any{"roleName": "Owned reader", "permissions": []any{map[string]any{"actions": []string{"Microsoft.Storage/*/read"}, "notActions": []string{"Microsoft.Storage/storageAccounts/listKeys/action"}, "dataActions": []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"}, "notDataActions": []string{}}}}}
		default:
			t.Errorf("unexpected ARM read %s", r.URL.Path)
			w.WriteHeader(400)
			return
		}
		_ = json.NewEncoder(w).Encode(reply)
	}))
	defer arm.Close()
	var refs []string
	for _, entry := range []struct {
		name  string
		value []byte
	}{{"TRSTCTL_A264_GRAPH_READER_PATH", graphAuthority}, {"TRSTCTL_A264_ARM_READER_PATH", armAuthority}} {
		path := filepath.Join(t.TempDir(), "reader")
		if err := os.WriteFile(path, entry.value, 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(entry.name, path)
		refs = append(refs, "env:"+entry.name)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, allowOutboundEnvCredentialRefs(refs...))
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "azure-inventory-operator", "discovery:read", "discovery:write", "graph:read", "nhi:read", string(authz.PrivateEgress))
	cfg := map[string]any{"azure_tenant_id": tenant, "subscription_id": subscription, "service_principal_ids": []string{principal}, "graph_token_file_ref": refs[0], "arm_token_file_ref": refs[1], "graph_endpoint": graph.URL, "arm_endpoint": arm.URL, "read_beta_signins": true, "activity_lookback_days": 30, "allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, graph.URL)}}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", operator, "a264-azure-source", map[string]any{"kind": "azure_machine_identity", "name": "Owned Azure workload inventory", "config": cfg})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil || source.ID == "" {
		t.Fatalf("Azure workload inventory source unavailable: %d %s", status, body)
	}
	runCapture := func(id string) string {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/runs", operator, id, map[string]any{"source_id": source.ID})
		var run struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &run) != nil {
			t.Fatalf("Azure capture unavailable: %d %s", status, body)
		}
		if err := h.srv.Drain(t.Context()); err != nil {
			t.Fatal(err)
		}
		return run.ID
	}
	runID := runCapture("a264-azure-run")
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+runID, operator, nil)
	var findings struct {
		Items []struct {
			Metadata json.RawMessage `json:"metadata"`
		} `json:"items"`
	}
	if status != 200 || json.Unmarshal(body, &findings) != nil || len(findings.Items) != 1 {
		t.Fatalf("Azure findings unavailable: %d %s", status, body)
	}
	metadata := findings.Items[0].Metadata
	for _, wanted := range []string{principal, key, "Orders.Read", "Microsoft.Storage/*/read", "notActions", "federation", "observed_only", "beta", now.Add(-time.Hour).Format(time.RFC3339)} {
		if !bytes.Contains(metadata, []byte(wanted)) {
			t.Fatalf("Azure evidence missing %s: %s", wanted, metadata)
		}
	}
	for _, forbidden := range [][]byte{graphAuthority, armAuthority, []byte("PRIVATE-CANARY-NOT-METADATA")} {
		if bytes.Contains(body, forbidden) {
			t.Fatal("Azure credential material leaked")
		}
	}
	if graphCalls.Load() < 5 || armCalls.Load() < 2 {
		t.Fatal("native Graph/ARM evidence was not read")
	}
	status, graphBody := secretsReq(t, h, http.MethodGet, "/api/v1/graph", operator, nil)
	if status != 200 || !bytes.Contains(graphBody, []byte("azure-key:")) || !bytes.Contains(graphBody, []byte("effective access is unknown")) {
		t.Fatal("Azure ownership/coverage graph missing")
	}
	var edges struct {
		Edges []struct {
			From string `json:"from"`
			Type string `json:"type"`
		} `json:"edges"`
	}
	if json.Unmarshal(graphBody, &edges) != nil {
		t.Fatal("graph unreadable")
	}
	for _, edge := range edges.Edges {
		if strings.HasPrefix(edge.From, "azure-") && edge.Type == "GRANTS_ACCESS" {
			t.Fatal("Azure metadata invented effective access")
		}
	}
	status, nhi := secretsReq(t, h, http.MethodGet, "/api/v1/nhi/inventory", operator, nil)
	if status != 200 || !bytes.Contains(nhi, []byte(`"kind":"service_account"`)) {
		t.Fatal("Azure NHI classification missing")
	}
	otherTenant := googleuuid.NewString()
	registerServedTenantID(t, h, otherTenant, "Azure isolation tenant")
	other := seedScopedToken(t, h.store, otherTenant, "discovery:read", "graph:read", "nhi:read")
	for _, path := range []string{"/api/v1/discovery/findings?run_id=" + runID, "/api/v1/graph", "/api/v1/nhi/inventory"} {
		status, foreign := secretsReq(t, h, http.MethodGet, path, other, nil)
		if status != 200 || bytes.Contains(foreign, []byte(principal)) {
			t.Fatal("foreign tenant read Azure evidence")
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
	status, replayed := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+runID, operator, nil)
	if status != 200 || !bytes.Equal(body, replayed) {
		t.Fatal("Azure inventory changed after rebuild")
	}
	denyRole.Store(true)
	partialID := runCapture("a264-azure-partial")
	partial, err := h.store.GetDiscoveryRun(t.Context(), h.tenant, partialID)
	if err != nil || partial.Status != "partial" || partial.Discovered != 1 {
		t.Fatal("unreadable role was reported complete")
	}
	wrongIdentity.Store(true)
	failedID := runCapture("a264-azure-wrong-id")
	failed, err := h.store.GetDiscoveryRun(t.Context(), h.tenant, failedID)
	if err != nil || failed.Status != "failed" || failed.Discovered != 0 {
		t.Fatal("different native workload accepted")
	}
	wrongIdentity.Store(false)
	denyRole.Store(false)
	managedIdentity.Store(true)
	cfg["managed_identity_resources"] = map[string]string{principal: "/subscriptions/" + subscription + "/resourceGroups/owned/providers/Microsoft.ManagedIdentity/userAssignedIdentities/worker"}
	cfg["read_beta_signins"] = false
	cfg["activity_lookback_days"] = 0
	status, newSource := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", operator, "a264-azure-managed-source", map[string]any{"kind": "azure_machine_identity", "name": "Owned managed identity inventory", "config": cfg})
	if status != http.StatusCreated || json.Unmarshal(newSource, &source) != nil {
		t.Fatalf("managed identity source refused: %d %s", status, newSource)
	}
	managedID := runCapture("a264-azure-managed-run")
	status, managedBody := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+managedID, operator, nil)
	if status != 200 || !bytes.Contains(managedBody, []byte("native_user_assigned_resource")) || !bytes.Contains(managedBody, []byte("user_assigned_identity_resource_only")) || !bytes.Contains(managedBody, []byte("owned-worker")) {
		t.Fatalf("managed identity native linkage/federation missing: %s", managedBody)
	}
	wrongTenant.Store(true)
	foreignTenantRun := runCapture("a264-azure-wrong-tenant")
	foreignRun, err := h.store.GetDiscoveryRun(t.Context(), h.tenant, foreignTenantRun)
	if err != nil || foreignRun.Status != "failed" || foreignRun.Discovered != 0 {
		t.Fatal("wrong native Graph tenant was accepted")
	}

}
