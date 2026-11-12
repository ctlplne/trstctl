// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/store"
)

// g2l2KubernetesStandIn is a Kubernetes API that issues lease service
// accounts as the provider asks and answers their RBAC: the RoleBinding the
// provider creates, and the Role it binds.
func g2l2KubernetesStandIn(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	objects := map[string]string{}          // path → uid
	bindings := map[string]map[string]any{} // name → posted RoleBinding
	sequence := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer g2l2-k8s-admin" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		const rb = "/apis/rbac.authorization.k8s.io/v1/namespaces/apps/rolebindings"
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/token"):
			_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]string{"token": "g2l2-k8s-lease-token", // #nosec G101 -- fabricated fixture credential; the stand-in needs the shape, no value is real (CWE-798)
				"expirationTimestamp": time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339)}})
		case r.Method == http.MethodPost:
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			meta, _ := body["metadata"].(map[string]any)
			name, _ := meta["name"].(string)
			sequence++
			objects[r.URL.Path+"/"+name] = fmt.Sprintf("uid-%d", sequence)
			if r.URL.Path == rb {
				bindings[name] = body
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"uid": objects[r.URL.Path+"/"+name], "labels": meta["labels"]}})
		case r.Method == http.MethodGet && r.URL.Path == rb:
			items := make([]map[string]any, 0, len(bindings))
			for _, b := range bindings {
				items = append(items, b)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
		case r.Method == http.MethodGet && r.URL.Path == "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{}})
		case r.Method == http.MethodGet && r.URL.Path == "/apis/rbac.authorization.k8s.io/v1/namespaces/apps/roles/g2l2-reader":
			_ = json.NewEncoder(w).Encode(map[string]any{"rules": []any{
				map[string]any{"verbs": []string{"get", "list"}, "apiGroups": []string{""}, "resources": []string{"configmaps"}},
			}})
		case r.Method == http.MethodGet:
			uid, ok := objects[r.URL.Path]
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"uid": uid}})
		case r.Method == http.MethodDelete:
			delete(objects, r.URL.Path)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{}"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// g2l2GCPStandIn is Google IAM and Resource Manager for one service account:
// it takes uploaded lease keys and answers the project's IAM policy.
func g2l2GCPStandIn(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	keys := map[string]string{} // key name → public key data
	const account = "projects/p/serviceAccounts/g2l2@p.iam.gserviceaccount.com"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer g2l2-gcp-admin" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/"+account+"/keys:upload":
			var body struct {
				PublicKeyData string `json:"publicKeyData"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			name := fmt.Sprintf("%s/keys/g2l2key%d", account, len(keys)+1)
			keys[name] = body.PublicKeyData
			_ = json.NewEncoder(w).Encode(map[string]string{"name": name})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/"+account+"/keys":
			listed := []map[string]string{}
			for name := range keys {
				listed = append(listed, map[string]string{"name": name})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": listed})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/"+account+"/keys/"):
			data, ok := keys[strings.TrimPrefix(r.URL.Path, "/v1/")]
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"name": strings.TrimPrefix(r.URL.Path, "/v1/"), "publicKeyData": data})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/"+account+"/keys/"):
			delete(keys, strings.TrimPrefix(r.URL.Path, "/v1/"))
			_, _ = w.Write([]byte("{}"))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/projects/p:getIamPolicy":
			_ = json.NewEncoder(w).Encode(map[string]any{"bindings": []any{
				map[string]any{"role": "roles/secretmanager.secretAccessor", "members": []string{"serviceAccount:g2l2@p.iam.gserviceaccount.com"}},
				map[string]any{"role": "roles/owner", "members": []string{"user:ops@example.com"}},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// g2l2AzureStandIn is Microsoft Graph for one application: it adds lease
// client secrets and answers the application's roles.
func g2l2AzureStandIn(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	passwords := map[string]string{} // key ID → display name
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer g2l2-azure-admin" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1.0/applications/app-obj/addPassword":
			var body struct {
				PasswordCredential struct {
					DisplayName string `json:"displayName"`
				} `json:"passwordCredential"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			key := fmt.Sprintf("g2l2-key-%d", len(passwords)+1)
			passwords[key] = body.PasswordCredential.DisplayName
			_ = json.NewEncoder(w).Encode(map[string]string{"keyId": key, "secretText": "g2l2-client-secret-" + key})
		case r.Method == http.MethodPost && r.URL.Path == "/v1.0/applications/app-obj/removePassword":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			delete(passwords, body["keyId"])
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/v1.0/applications/app-obj":
			listed := []map[string]string{}
			for key, name := range passwords {
				listed = append(listed, map[string]string{"keyId": key, "displayName": name})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"appId": "g2l2-client", "passwordCredentials": listed})
		case r.Method == http.MethodGet && r.URL.Path == "/v1.0/servicePrincipals" && r.URL.Query().Get("$filter") == "appId eq 'g2l2-client'":
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{map[string]string{"id": "sp-g2l2"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1.0/servicePrincipals/sp-g2l2/appRoleAssignments":
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{
				map[string]string{"resourceId": "graph-sp", "resourceDisplayName": "Microsoft Graph", "appRoleId": "role-read-apps"},
			}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1.0/servicePrincipals/graph-sp":
			_ = json.NewEncoder(w).Encode(map[string]any{"appRoles": []any{map[string]string{"id": "role-read-apps", "value": "Application.Read.All"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1.0/servicePrincipals/sp-g2l2/memberOf":
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestServedLeaseAccessReadsKubernetesGCPAndAzureG2L2 is G2-L2 for cluster
// and cloud identities, through providers configured as the binary
// configures them against stand-ins of the Kubernetes API, Google IAM and
// Resource Manager, and Microsoft Graph. A Kubernetes lease links to its
// namespace with the rules the cluster's RBAC grants its service account; a
// GCP lease to its service account with the roles the project's IAM policy
// grants it; an Azure lease to its application with its app roles. A key the
// provider no longer has reads as unknown (login_missing), never as none.
func TestServedLeaseAccessReadsKubernetesGCPAndAzureG2L2(t *testing.T) {
	k8s, gcp, azure := g2l2KubernetesStandIn(t), g2l2GCPStandIn(t), g2l2AzureStandIn(t)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnableSecretsAPI = true
		resolver := integrationCredentialResolver{store: d.Store, kek: d.KEK, crypto: d.TenantCrypto}
		reader := map[string]bool{"reader": true}
		providers := []config.DynamicSecretProviderConfig{
			{TenantID: servedTestTenant, ID: "cluster-g2l2", Type: "kubernetes", Endpoint: k8s.URL, Namespace: "apps",
				KubernetesAudience: "https://kubernetes.default.svc", BearerTokenRef: writeServedCredentialFile(t, "g2l2-k8s-admin", "g2l2-k8s-admin"),
				AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "Role/g2l2-reader"}, MaxTTL: "15m",
				AllowInsecureLoopback: true, UsernamePrefix: "g2l2-k8s"},
			{TenantID: servedTestTenant, ID: "gcp-g2l2", Type: "gcp-iam", Endpoint: gcp.URL, IAMEndpoint: gcp.URL, Project: "p",
				ServiceAccount: "g2l2@p.iam.gserviceaccount.com", BearerTokenRef: writeServedCredentialFile(t, "g2l2-gcp-admin", "g2l2-gcp-admin"),
				AllowedRoles: []string{"reader"}, MaxTTL: "15m", AllowInsecureLoopback: true, UsernamePrefix: "g2l2-gcp"},
			{TenantID: servedTestTenant, ID: "azure-g2l2", Type: "azure-entra", Endpoint: azure.URL, ApplicationObject: "app-obj",
				ApplicationClient: "g2l2-client", AzureTenant: "g2l2-tenant", BearerTokenRef: writeServedCredentialFile(t, "g2l2-azure-admin", "g2l2-azure-admin"),
				AllowedRoles: []string{"reader"}, MaxTTL: "15m", AllowInsecureLoopback: true, UsernamePrefix: "g2l2-azure"},
		}
		if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: providers}, true); err != nil {
			t.Fatalf("providers: %v", err)
		}
		var configured []dynsecret.Provider
		for _, p := range providers {
			configured = append(configured, newConfiguredDynamicProvider(p, reader, 15*time.Minute, resolver, nil))
		}
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: configured}
		d.DynamicSecretAccessInterval = time.Hour // the test drives each read itself
	})
	startServedExternalCADispatcher(t, h)
	ctx := t.Context()
	issuer := seedScopedTokenSubject(t, h.store, h.tenant, "g2l2-cloud-issuer", "secrets:read", "secrets:write")
	reader := seedScopedTokenSubject(t, h.store, h.tenant, "g2l2-cloud-reader", "graph:read", "access:read")
	resolve := func() {
		t.Helper()
		if err := h.srv.ResolveDynamicSecretAccessOnce(ctx); err != nil {
			t.Fatalf("lease access pass: %v", err)
		}
	}
	k8sLease, _ := issueG2Lease(t, h, issuer, "g2l2-k8s-1", "cluster-g2l2", "reader")
	gcpLease, _ := issueG2Lease(t, h, issuer, "g2l2-gcp-1", "gcp-g2l2", "reader")
	azureLease, _ := issueG2Lease(t, h, issuer, "g2l2-azure-1", "azure-g2l2", "reader")
	resolve()
	g := readG2Graph(t, h, reader)

	for _, tc := range []struct {
		lease, provider, kind, resourceKind, target, grant, login string
	}{
		{k8sLease, "cluster-g2l2", "kubernetes_namespace", "kubernetes_namespace", "kubernetes://" + strings.TrimPrefix(k8s.URL, "http://") + "/namespaces/apps",
			"Role g2l2-reader in namespace apps: get, list on configmaps", "system:serviceaccount:apps:g2l2-k8s"},
		{gcpLease, "gcp-g2l2", "gcp_service_account", "cloud_identity", "gcp://projects/p/serviceAccounts/g2l2@p.iam.gserviceaccount.com",
			"role roles/secretmanager.secretAccessor on project p", "projects/p/serviceAccounts/g2l2@p.iam.gserviceaccount.com/keys/"},
		{azureLease, "azure-g2l2", "azure_application", "cloud_identity", "azure://applications/app-obj",
			"app role Application.Read.All on Microsoft Graph", "g2l2-key-"},
	} {
		n, ok := g.node("lease:" + tc.lease)
		if !ok || n.Attrs["access_status"] != store.DynamicSecretAccessResolved || n.Attrs["grants"] != tc.grant || n.Attrs["target"] != tc.target ||
			!strings.HasPrefix(n.Attrs["login"], tc.login) {
			t.Fatalf("%s lease = %+v (present %v); want %q on %s", tc.provider, n.Attrs, ok, tc.grant, tc.target)
		}
		node := "res:" + tc.kind + ":" + tc.target
		res, ok := g.node(node)
		if !ok || res.Attrs["resource_kind"] != tc.resourceKind || !g.edge("lease:"+tc.lease, node, "GRANTS_ACCESS") ||
			!g.edge("res:dynamic-secret:"+tc.provider, node, "CONNECTS_TO") {
			t.Fatalf("%s: no grants-access link to %s: %+v (present %v)", tc.provider, node, res, ok)
		}
	}

	// The Azure lease's secret removed at the directory: unknown (login_missing), still linked.
	removeAzureSecret := func() {
		t.Helper()
		n, _ := g.node("lease:" + azureLease)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, azure.URL+"/v1.0/applications/app-obj/removePassword",
			strings.NewReader(`{"keyId":"`+n.Attrs["login"]+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer g2l2-azure-admin")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	removeAzureSecret()
	if _, err := h.store.SystemPool().Exec(ctx,
		`UPDATE dynamic_secret_lease_access SET checked_at = checked_at - interval '7 hours', rechecked_at = NULL WHERE tenant_id = $1 AND lease_id = $2`,
		h.tenant, azureLease); err != nil {
		t.Fatal(err)
	}
	resolve()
	g = readG2Graph(t, h, reader)
	if n, _ := g.node("lease:" + azureLease); n.Attrs["access_status"] != store.DynamicSecretAccessUnknown || n.Attrs["access_reason"] != "login_missing" ||
		!g.edge("lease:"+azureLease, "res:azure_application:azure://applications/app-obj", "GRANTS_ACCESS") {
		t.Fatalf("an Azure secret the directory no longer has = %+v; want unknown (login_missing), still linked", n.Attrs)
	}
	for _, leaked := range []string{"g2l2-k8s-admin", "g2l2-gcp-admin", "g2l2-azure-admin", "g2l2-k8s-lease-token", "g2l2-client-secret-"} {
		if h.logContains(t, leaked) {
			t.Fatalf("%q reached the event log", leaked)
		}
	}
}
