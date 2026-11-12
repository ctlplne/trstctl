// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

// k8sRBACDouble answers the reads a Kubernetes lease access needs: the
// service account, the namespace's RoleBindings and the cluster's
// ClusterRoleBindings, and the roles they bind.
func k8sRBACDouble(t *testing.T, accountUID string, denyBindings *atomic.Bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sa-token" || r.Method != http.MethodGet {
			http.Error(w, "refused", http.StatusUnauthorized)
			return
		}
		sa := map[string]string{"kind": "ServiceAccount", "name": "trstctl-lease-1", "namespace": "apps"}
		switch r.URL.Path {
		case "/api/v1/namespaces/apps/serviceaccounts/trstctl-lease-1":
			if accountUID == "" {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]string{"uid": accountUID}})
		case "/apis/rbac.authorization.k8s.io/v1/namespaces/apps/rolebindings":
			if denyBindings != nil && denyBindings.Load() {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{
				map[string]any{"metadata": map[string]string{"name": "trstctl-lease-1"}, "subjects": []any{sa},
					"roleRef": map[string]string{"kind": "Role", "name": "reader"}},
				map[string]any{"metadata": map[string]string{"name": "someone-else"},
					"subjects": []any{map[string]string{"kind": "ServiceAccount", "name": "other", "namespace": "apps"}},
					"roleRef":  map[string]string{"kind": "ClusterRole", "name": "admin"}},
			}})
		case "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{
				map[string]any{"metadata": map[string]string{"name": "deploy-view"}, "subjects": []any{sa},
					"roleRef": map[string]string{"kind": "ClusterRole", "name": "deploy-view"}},
			}})
		case "/apis/rbac.authorization.k8s.io/v1/namespaces/apps/roles/reader":
			_ = json.NewEncoder(w).Encode(map[string]any{"rules": []any{
				map[string]any{"verbs": []string{"get", "list"}, "apiGroups": []string{""}, "resources": []string{"pods", "configmaps"}},
			}})
		case "/apis/rbac.authorization.k8s.io/v1/clusterroles/deploy-view":
			_ = json.NewEncoder(w).Encode(map[string]any{"rules": []any{
				map[string]any{"verbs": []string{"get"}, "apiGroups": []string{"apps"}, "resources": []string{"deployments"}, "resourceNames": []string{"web"}},
				map[string]any{"verbs": []string{"get"}, "nonResourceURLs": []string{"/healthz"}},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func k8sAccessBackend(t *testing.T, srv *httptest.Server) *KubernetesBackend {
	t.Helper()
	b, err := NewKubernetesBackend(KubernetesConfig{Endpoint: srv.URL, HTTPClient: srv.Client(), Namespace: "apps",
		Audience: "https://kubernetes.default.svc", BearerToken: []byte("sa-token"), UsernamePrefix: "trstctl"})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestKubernetesLeaseAccessReadsTheServiceAccountsRBACG2L2 reads what a
// lease's service account may do: each RoleBinding and ClusterRoleBinding
// naming it, with its role's rules; bindings naming another account are left
// out. A deleted or replaced account is a missing login, and RBAC the admin
// may not list is denied.
func TestKubernetesLeaseAccessReadsTheServiceAccountsRBACG2L2(t *testing.T) {
	ctx := context.Background()
	ref := `{"version":1,"name":"trstctl-lease-1","service_account_uid":"uid-1","bound_secret_uid":"uid-2"}`
	var deny atomic.Bool
	srv := k8sRBACDouble(t, "uid-1", &deny)
	access, err := k8sAccessBackend(t, srv).ResolveAccess(ctx, ref)
	if err != nil || access.TargetKind != AccessTargetKubernetesNamespace || access.Login != "system:serviceaccount:apps:trstctl-lease-1" ||
		access.TargetRef != "kubernetes://"+strings.TrimPrefix(srv.URL, "http://")+"/namespaces/apps" {
		t.Fatalf("Kubernetes access = %+v, %v", access, err)
	}
	want := []string{
		"ClusterRole deploy-view cluster-wide: get on /healthz",
		"ClusterRole deploy-view cluster-wide: get on deployments (apps) named web",
		"Role reader in namespace apps: get, list on pods, configmaps",
	}
	if !slices.Equal(access.Grants, want) {
		t.Fatalf("Kubernetes grants = %q, want %q", access.Grants, want)
	}
	deny.Store(true)
	if _, err := k8sAccessBackend(t, srv).ResolveAccess(ctx, ref); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("RBAC the admin may not list = %v, want denied", err)
	}
	if _, err := k8sAccessBackend(t, k8sRBACDouble(t, "", nil)).ResolveAccess(ctx, ref); !errors.Is(err, ErrAccessLoginMissing) {
		t.Fatalf("a deleted service account = %v, want login missing", err)
	}
	if _, err := k8sAccessBackend(t, k8sRBACDouble(t, "uid-other", nil)).ResolveAccess(ctx, ref); !errors.Is(err, ErrAccessLoginMissing) {
		t.Fatalf("a replaced service account = %v, want login missing", err)
	}
}

// gcpPolicyDouble answers a key read and the project's IAM policy.
func gcpPolicyDouble(t *testing.T, keyExists bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gcp-token" {
			http.Error(w, "refused", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/projects/p/serviceAccounts/dyn@p.iam.gserviceaccount.com/keys/k1":
			if !keyExists {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"name": "projects/p/serviceAccounts/dyn@p.iam.gserviceaccount.com/keys/k1"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/projects/p:getIamPolicy":
			_ = json.NewEncoder(w).Encode(map[string]any{"bindings": []any{
				map[string]any{"role": "roles/viewer", "members": []string{"serviceAccount:dyn@p.iam.gserviceaccount.com", "user:ops@example.com"}},
				map[string]any{"role": "roles/storage.objectViewer", "members": []string{"serviceAccount:dyn@p.iam.gserviceaccount.com"},
					"condition": map[string]string{"title": "logs bucket only"}},
				map[string]any{"role": "roles/owner", "members": []string{"user:ops@example.com"}},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestGCPLeaseAccessReadsTheProjectPolicyG2L2 reads the roles the project's
// IAM policy grants the lease key's service account, with a binding's
// condition; bindings for other members are left out. A deleted key is a
// missing login, and a key of another account is refused.
func TestGCPLeaseAccessReadsTheProjectPolicyG2L2(t *testing.T) {
	ctx := context.Background()
	backend := func(srv *httptest.Server) *GCPIAMBackend {
		b, err := NewGCPIAMBackend(GCPIAMConfig{Endpoint: srv.URL, HTTPClient: srv.Client(), Project: "p", ServiceAccountEmail: "dyn@p.iam.gserviceaccount.com",
			BearerToken: []byte("gcp-token"), PolicyEndpoint: srv.URL})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	const key = "projects/p/serviceAccounts/dyn@p.iam.gserviceaccount.com/keys/k1"
	access, err := backend(gcpPolicyDouble(t, true)).ResolveAccess(ctx, key)
	want := []string{"role roles/storage.objectViewer on project p when logs bucket only", "role roles/viewer on project p"}
	if err != nil || access.TargetKind != AccessTargetGCPServiceAccount || access.TargetRef != "gcp://projects/p/serviceAccounts/dyn@p.iam.gserviceaccount.com" ||
		access.Login != key || !slices.Equal(access.Grants, want) {
		t.Fatalf("GCP access = %+v, %v; want %q", access, err, want)
	}
	if _, err := backend(gcpPolicyDouble(t, false)).ResolveAccess(ctx, key); !errors.Is(err, ErrAccessLoginMissing) {
		t.Fatalf("a deleted key = %v, want login missing", err)
	}
	if _, err := backend(gcpPolicyDouble(t, true)).ResolveAccess(ctx, "projects/p/serviceAccounts/other@p.iam.gserviceaccount.com/keys/k1"); !errors.Is(err, ErrAccessLoginMissing) {
		t.Fatalf("a key of another account = %v, want refused as no login of this provider", err)
	}
}

// azureDirectoryDouble answers the reads an Azure lease access needs from
// Microsoft Graph.
func azureDirectoryDouble(t *testing.T, keys ...string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer az-token" || r.Method != http.MethodGet {
			http.Error(w, "refused", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1.0/applications/app-obj":
			credentials := []map[string]string{}
			for _, k := range keys {
				credentials = append(credentials, map[string]string{"keyId": k})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"appId": "app-client", "passwordCredentials": credentials})
		case "/v1.0/servicePrincipals":
			if r.URL.Query().Get("$filter") != "appId eq 'app-client'" {
				http.Error(w, "bad filter", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{map[string]string{"id": "sp-1"}}})
		case "/v1.0/servicePrincipals/sp-1/appRoleAssignments":
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{
				map[string]string{"resourceId": "graph-sp", "resourceDisplayName": "Microsoft Graph", "appRoleId": "role-1"},
			}})
		case "/v1.0/servicePrincipals/graph-sp":
			_ = json.NewEncoder(w).Encode(map[string]any{"appRoles": []any{map[string]string{"id": "role-1", "value": "User.Read.All"}}})
		case "/v1.0/servicePrincipals/sp-1/memberOf":
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{
				map[string]string{"@odata.type": "#microsoft.graph.directoryRole", "displayName": "Cloud Application Administrator"},
				map[string]string{"@odata.type": "#microsoft.graph.group", "displayName": "deployers"},
			}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestAzureLeaseAccessReadsTheApplicationsRolesG2L2 reads what the lease's
// application may do in the directory: its app role assignments by role
// value, its directory roles and groups. A removed secret is a missing login.
func TestAzureLeaseAccessReadsTheApplicationsRolesG2L2(t *testing.T) {
	ctx := context.Background()
	backend := func(srv *httptest.Server) *AzureEntraBackend {
		b, err := NewAzureEntraBackend(AzureEntraConfig{Endpoint: srv.URL, HTTPClient: srv.Client(), ApplicationObjectID: "app-obj", BearerToken: []byte("az-token")})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	access, err := backend(azureDirectoryDouble(t, "key-1")).ResolveAccess(ctx, "key-1")
	want := []string{"app role User.Read.All on Microsoft Graph", "directory role Cloud Application Administrator", "member of group deployers"}
	if err != nil || access.TargetKind != AccessTargetAzureApplication || access.TargetRef != "azure://applications/app-obj" || access.Login != "key-1" ||
		!slices.Equal(access.Grants, want) {
		t.Fatalf("Azure access = %+v, %v; want %q", access, err, want)
	}
	if _, err := backend(azureDirectoryDouble(t, "key-2")).ResolveAccess(ctx, "key-1"); !errors.Is(err, ErrAccessLoginMissing) {
		t.Fatalf("a removed client secret = %v, want login missing", err)
	}
}
