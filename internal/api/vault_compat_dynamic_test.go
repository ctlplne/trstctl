// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/dynsecret"
)

// vaultShimProvider is a configured provider as the Vault paths see it.
type vaultShimProvider struct {
	id, providerType, namespace, audience string
	roles                                 []string
	bindings                              map[string]string
	maxTTL                                time.Duration
}

func (p vaultShimProvider) Name() string                               { return p.id }
func (p vaultShimProvider) DynamicSecretProviderType() string          { return p.providerType }
func (p vaultShimProvider) DynamicSecretAllowedRoles() []string        { return p.roles }
func (p vaultShimProvider) DynamicSecretConfigurationRevision() string { return "rev-" + p.id }
func (p vaultShimProvider) MaximumTTL() time.Duration                  { return p.maxTTL }
func (p vaultShimProvider) DynamicSecretKubernetesScope() (string, string) {
	return p.namespace, p.audience
}
func (p vaultShimProvider) DynamicSecretBindsRole(role, binding string) bool {
	return p.bindings[role] != "" && p.bindings[role] == binding
}
func (p vaultShimProvider) Generate(context.Context, dynsecret.GenerateRequest) (dynsecret.Credential, error) {
	return dynsecret.Credential{}, nil
}
func (p vaultShimProvider) Revoke(context.Context, string) error { return nil }

func vaultShimSecrets(providers ...dynsecret.Provider) *secretsService {
	return &secretsService{be: SecretsBackend{DynamicProvidersForTenant: func(string) []dynsecret.Provider { return providers }}}
}

func TestVaultDynamicMountsResolveOneProviderPerRole(t *testing.T) {
	s := vaultShimSecrets(
		vaultShimProvider{id: "app-postgres", providerType: "postgresql", roles: []string{"readonly"}, maxTTL: time.Hour},
		vaultShimProvider{id: "billing-mysql", providerType: "mysql", roles: []string{"readonly", "writer"}, maxTTL: time.Hour},
		vaultShimProvider{id: "apps-k8s", providerType: "kubernetes", roles: []string{"reader"}, maxTTL: time.Hour},
		vaultShimProvider{id: "aws-deploy", providerType: "aws-sts", roles: []string{"deployer"}, maxTTL: time.Hour},
		vaultShimProvider{id: "gcp-view", providerType: "gcp-iam", roles: []string{"viewer"}, maxTTL: time.Hour},
	)
	for _, c := range []struct {
		mount, kind, role string
		found             bool
		provider, refusal string
	}{
		{"database", "creds", "writer", true, "billing-mysql", ""},
		{"database", "creds", "readonly", true, "", "offered by providers app-postgres, billing-mysql"},
		{"app-postgres", "creds", "readonly", true, "app-postgres", ""},
		{"database", "creds", "nope", true, "", "unknown role: nope"},
		{"app-postgres", "creds", "writer", true, "", "unknown role: writer"},
		{"kubernetes", "creds", "reader", true, "apps-k8s", ""},
		{"aws", "creds", "deployer", true, "aws-deploy", ""},
		{"aws", "sts", "deployer", true, "aws-deploy", ""},
		{"aws-deploy", "sts", "deployer", true, "aws-deploy", ""},
		{"gcp-view", "creds", "viewer", true, "", "has no Vault engine shape"},
		{"database", "sts", "writer", false, "", ""},
		{"app-postgres", "sts", "readonly", false, "", ""},
		{"cubbyhole", "creds", "note", false, "", ""},
	} {
		target, found, err := s.resolveVaultDynamicTarget("tenant-a", c.mount, c.kind, c.role)
		name := c.mount + "/" + c.kind + "/" + c.role
		if found != c.found {
			t.Fatalf("%s found = %v, want %v", name, found, c.found)
		}
		switch {
		case c.refusal != "":
			if err == nil || !strings.Contains(err.Error(), c.refusal) || vaultHTTPStatus(err) != http.StatusBadRequest {
				t.Fatalf("%s refusal = %v, want 400 containing %q", name, err, c.refusal)
			}
		case c.found:
			if err != nil || target.provider.ID != c.provider {
				t.Fatalf("%s = %+v %v, want provider %s", name, target, err, c.provider)
			}
		}
	}
	// A tenant without any Kubernetes provider has no kubernetes/ engine: the
	// path belongs to the shim's other mounts.
	if _, found, _ := vaultShimSecrets(vaultShimProvider{id: "pg", providerType: "postgresql", roles: []string{"ro"}}).
		resolveVaultDynamicTarget("tenant-a", "kubernetes", "creds", "reader"); found {
		t.Fatal("kubernetes/ resolved for a tenant with no Kubernetes provider")
	}
}

func TestVaultDynamicParametersAreCheckedAgainstTheProvider(t *testing.T) {
	k8s := vaultDynamicTarget{engine: vaultKubernetesEngine, role: "reader", provider: dynamicSecretConfiguredProvider{MaximumTTLSeconds: 7200}}
	k8sScope := vaultShimProvider{namespace: "apps", audience: "https://kubernetes.default.svc"}
	aws := vaultDynamicTarget{engine: vaultAWSEngine, role: "deployer", provider: dynamicSecretConfiguredProvider{MaximumTTLSeconds: 1800}}
	awsScope := vaultShimProvider{bindings: map[string]string{"deployer": "arn:aws:iam::000000000000:role/deployer"}}
	db := vaultDynamicTarget{engine: vaultDatabaseEngine, role: "readonly", provider: dynamicSecretConfiguredProvider{MaximumTTLSeconds: 600}}
	for _, c := range []struct {
		name    string
		target  vaultDynamicTarget
		scope   vaultDynamicProviderScope
		params  map[string]string
		ttl     time.Duration
		refusal string
	}{
		{"kubernetes default", k8s, k8sScope, map[string]string{"kubernetes_namespace": "apps"}, time.Hour, ""},
		{"kubernetes ttl", k8s, k8sScope, map[string]string{"ttl": "90m", "audiences": "https://kubernetes.default.svc"}, 90 * time.Minute, ""},
		{"kubernetes seconds", k8s, k8sScope, map[string]string{"ttl": "1200"}, 20 * time.Minute, ""},
		{"kubernetes other namespace", k8s, k8sScope, map[string]string{"kubernetes_namespace": "kube-system"}, 0, "not this role's namespace apps"},
		{"kubernetes cluster binding", k8s, k8sScope, map[string]string{"cluster_role_binding": "true"}, 0, "cluster_role_binding is not supported"},
		{"kubernetes other audience", k8s, k8sScope, map[string]string{"audiences": "vault"}, 0, "audiences must be"},
		{"aws capped default", aws, awsScope, nil, 30 * time.Minute, ""},
		{"aws role_arn", aws, awsScope, map[string]string{"role_arn": "arn:aws:iam::000000000000:role/deployer", "ttl": "15m"}, 15 * time.Minute, ""},
		{"aws other role_arn", aws, awsScope, map[string]string{"role_arn": "arn:aws:iam::000000000000:role/admin"}, 0, "is not the role deployer assumes"},
		{"aws session name", aws, awsScope, map[string]string{"role_session_name": "mine"}, 0, "role_session_name is not supported"},
		{"aws mfa", aws, awsScope, map[string]string{"mfa_code": "123456"}, 0, "mfa_code is not supported"},
		{"aws bad ttl", aws, awsScope, map[string]string{"ttl": "soon"}, 0, "ttl: must be seconds"},
		{"database ignores ttl", db, nil, map[string]string{"ttl": "1h"}, 10 * time.Minute, ""},
	} {
		ttl, err := vaultDynamicLeaseTTL(c.target, c.params, c.scope)
		if c.refusal != "" {
			if err == nil || !strings.Contains(err.Error(), c.refusal) {
				t.Fatalf("%s: %v, want %q", c.name, err, c.refusal)
			}
			continue
		}
		if err != nil || ttl != c.ttl {
			t.Fatalf("%s: ttl %s %v, want %s", c.name, ttl, err, c.ttl)
		}
	}
}

func TestVaultDynamicCredentialShapes(t *testing.T) {
	db, err := vaultDynamicCredentialShape(vaultDynamicTarget{engine: vaultDatabaseEngine, provider: dynamicSecretConfiguredProvider{Type: "postgresql"}},
		nil, dynsecret.Lease{}, []byte("postgres://v_ro:s3cr3t@db.internal:5432/app?sslmode=verify-full"))
	if err != nil || db.Username != "v_ro" || string(db.Password) != "s3cr3t" || db.AccessKey != "" {
		t.Fatalf("database shape = %+v %v", db, err)
	}
	aws, err := vaultDynamicCredentialShape(vaultDynamicTarget{engine: vaultAWSEngine, provider: dynamicSecretConfiguredProvider{Type: "aws-sts"}},
		nil, dynsecret.Lease{BackendRef: `{"role_arn":"arn:aws:iam::000000000000:role/deployer","session_name":"s1"}`},
		[]byte(`{"access_key_id":"ASIAEXAMPLE","secret_access_key":"sk","session_token":"st","expiration":"2026-10-27T12:00:00Z"}`))
	if err != nil || aws.AccessKey != "ASIAEXAMPLE" || string(aws.SecretKey) != "sk" || string(aws.SessionToken) != "st" ||
		aws.ARN != "arn:aws:sts::000000000000:assumed-role/deployer/s1" {
		t.Fatalf("aws shape = %+v %v", aws, err)
	}
	k8s, err := vaultDynamicCredentialShape(vaultDynamicTarget{engine: vaultKubernetesEngine, provider: dynamicSecretConfiguredProvider{Type: "kubernetes"}},
		vaultShimProvider{namespace: "apps"}, dynsecret.Lease{BackendRef: `{"version":1,"name":"trstctl-reader-1"}`}, []byte("eyJ.token"))
	if err != nil || k8s.ServiceAccountName != "trstctl-reader-1" || k8s.ServiceAccountNamespace != "apps" || string(k8s.ServiceAccountToken) != "eyJ.token" {
		t.Fatalf("kubernetes shape = %+v %v", k8s, err)
	}
	if _, err := vaultDynamicCredentialShape(vaultDynamicTarget{engine: vaultAWSEngine}, nil, dynsecret.Lease{}, []byte(`{"secret_access_key":"sk"}`)); err == nil {
		t.Fatal("an AWS credential without an access key id was accepted")
	}
}

func TestVaultLeaseCommandKeyReplaysAnExplicitKeyOnly(t *testing.T) {
	explicit := httptest.NewRequest(http.MethodGet, "/v1/database/creds/readonly", nil)
	explicit.Header.Set("Idempotency-Key", "operator-key")
	if key, ok := vaultLeaseCommandKey(httptest.NewRecorder(), explicit); !ok || key != "operator-key" {
		t.Fatalf("explicit key = %q %v", key, ok)
	}
	stock := httptest.NewRequest(http.MethodGet, "/v1/database/creds/readonly", nil)
	first, ok1 := vaultLeaseCommandKey(httptest.NewRecorder(), stock)
	second, ok2 := vaultLeaseCommandKey(httptest.NewRecorder(), stock)
	if !ok1 || !ok2 || first == second || !strings.HasPrefix(first, "vault-lease-v1-") {
		t.Fatalf("stock-client keys = %q %q; each read must open its own lease", first, second)
	}
}

func TestVaultParseSecondsAcceptsSecondsAndDurations(t *testing.T) {
	for raw, want := range map[string]time.Duration{"3600": time.Hour, "1h": time.Hour, "90m": 90 * time.Minute, "1500ms": time.Second} {
		if got, err := parseVaultSeconds(raw); err != nil || got != want {
			t.Fatalf("%q = %s %v, want %s", raw, got, err, want)
		}
	}
	for _, raw := range []string{"0", "-5", "soon", "-1h"} {
		if got, err := parseVaultSeconds(raw); err == nil {
			t.Fatalf("%q = %s, want an error", raw, got)
		}
	}
}

func TestVaultDynamicRoutesAreServed(t *testing.T) {
	h := New(nil, nil, nil)
	for _, rt := range vaultCompatDynamicRoutes {
		req := httptest.NewRequest(rt.method, rt.samplePath, strings.NewReader(rt.sampleBody))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
			t.Fatalf("%s %s = %d; the route is not served", rt.method, rt.samplePath, rec.Code)
		}
	}
}
