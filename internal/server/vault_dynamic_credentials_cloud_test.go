// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// TestServedVaultAWSCredentialsOnLocalStack is A203 for AWS: the stock CLI reads
// an STS session at aws/creds/<role> and aws/sts/<role> from an aws-sts provider
// pointed at LocalStack, and AWS's own sts get-caller-identity (the AWS CLI in
// the LocalStack container) reports the assumed-role ARN the response names.
// STS cannot end one session early, so a synchronous revoke refuses and says
// so; an asynchronous revoke is queued, the lease is revoked and its provider
// status stays pending until the session's native expiry. LocalStack does not
// enforce IAM, so this proves the wire shapes and lease lifecycle, not AWS
// authorization.
func TestServedVaultAWSCredentialsOnLocalStack(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	vault := vaultCLIBinary(t)
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required: %v", err)
	}
	if out, err := exec.Command("docker", "image", "inspect", a202LocalStackImage).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Skipf("the pinned LocalStack image is not present locally: %v\n%s", err, out)
	}
	ctx := context.Background()
	localstack, address := a201Container(t, "4566", "-e", "SERVICES=iam,sts", a202LocalStackImage)
	endpoint := "http://" + address
	a201Await(t, "LocalStack STS", func() bool {
		resp, err := http.Get(endpoint + "/_localstack/health")
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		var health struct{ Services map[string]string }
		return json.NewDecoder(resp.Body).Decode(&health) == nil &&
			(health.Services["sts"] == "available" || health.Services["sts"] == "running")
	})
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}]}`
	if out, err := a201Exec(localstack, "awslocal", "iam", "create-role", "--role-name", "a203-deployer", "--assume-role-policy-document", trust); err != nil {
		t.Fatalf("create the role: %v %s", err, out)
	}
	roleARN := "arn:aws:iam::000000000000:role/a203-deployer"
	registry, err := dynamicSecretProvidersFromConfig(ctx, []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "aws-deploy", Type: "aws-sts", Endpoint: endpoint, AllowInsecureLoopback: true,
		Region: "us-east-1", AccessKeyID: "test", SecretAccessRef: writeServedCredentialFile(t, "aws-secret", "test"),
		AllowedRoles: []string{"deployer"}, RoleBindings: map[string]string{"deployer": roleARN}, MaxTTL: "1h",
		UsernamePrefix: "trstctl-a203",
	}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenant(t, h, "Vault AWS credentials tenant")
	startServedExternalCADispatcher(t, h)
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	home := t.TempDir()

	creds := decodeVaultLease(t, runVault(t, vault, home, h.ts.URL, token, "read", "-format=json", "aws/creds/deployer"))
	if !strings.HasPrefix(creds.LeaseID, "aws/creds/deployer/lease-") || creds.Renewable || creds.LeaseDuration < 3590 ||
		creds.Data["access_key"] == "" || creds.Data["secret_key"] == "" || creds.Data["session_token"] == "" ||
		!strings.HasPrefix(creds.Data["arn"], "arn:aws:sts::000000000000:assumed-role/a203-deployer/") {
		t.Fatalf("aws/creds read = lease %s renewable %v duration %d arn %q keys %v", creds.LeaseID, creds.Renewable, creds.LeaseDuration, creds.Data["arn"], len(creds.Data))
	}
	callerIdentity := func(lease vaultLeaseOutput) string {
		t.Helper()
		cmd := exec.Command("docker", "exec", // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
			"-e", "AWS_ACCESS_KEY_ID="+lease.Data["access_key"], "-e", "AWS_SECRET_ACCESS_KEY="+lease.Data["secret_key"],
			"-e", "AWS_SESSION_TOKEN="+lease.Data["session_token"], localstack,
			"aws", "--endpoint-url", "http://localhost:4566", "--region", "us-east-1", "sts", "get-caller-identity")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("sts get-caller-identity: %v %s", err, out)
		}
		var identity struct{ Arn string }
		if err := json.Unmarshal(out, &identity); err != nil {
			t.Fatalf("decode the caller identity: %v %s", err, out)
		}
		return identity.Arn
	}
	if arn := callerIdentity(creds); arn != creds.Data["arn"] {
		t.Fatalf("AWS says the session is %s; the Vault response says %s", arn, creds.Data["arn"])
	}

	sts := decodeVaultLease(t, runVault(t, vault, home, h.ts.URL, token, "read", "-format=json", "aws/sts/deployer", "ttl=15m"))
	if !strings.HasPrefix(sts.LeaseID, "aws/sts/deployer/") || sts.LeaseDuration < 890 || sts.LeaseDuration > 900 || callerIdentity(sts) != sts.Data["arn"] {
		t.Fatalf("aws/sts read = %s %d %s", sts.LeaseID, sts.LeaseDuration, sts.Data["arn"])
	}
	if sts.Data["access_key"] == creds.Data["access_key"] {
		t.Fatal("two reads returned the same session")
	}

	failure := runVaultExpectingFailure(t, vault, home, h.ts.URL, token, "lease", "renew", creds.LeaseID)
	if !strings.Contains(string(failure), "lease is not renewable") {
		t.Fatalf("renew of an STS lease = %s", failure)
	}
	failure = runVaultExpectingFailure(t, vault, home, h.ts.URL, token, "lease", "revoke", "-sync", creds.LeaseID)
	if !strings.Contains(string(failure), "AWS cannot end an STS session early") {
		t.Fatalf("lease revoke -sync of an STS lease = %s", failure)
	}
	if out := runVault(t, vault, home, h.ts.URL, token, "lease", "revoke", sts.LeaseID); !strings.Contains(string(out), "queued successfully") {
		t.Fatalf("lease revoke = %s", out)
	}
	for _, lease := range []vaultLeaseOutput{creds, sts} {
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+nativeLeaseID(t, lease.LeaseID), token, nil)
		var native struct {
			State            string     `json:"state"`
			RevocationStatus string     `json:"revocation_status"`
			NativeExpiresAt  *time.Time `json:"native_expires_at"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &native) != nil || native.State != "revoked" ||
			native.RevocationStatus != "pending" || native.NativeExpiresAt == nil || !native.NativeExpiresAt.After(time.Now()) {
			t.Fatalf("native lease after revoke = %d %s, want revoked and pending until the native expiry", status, body)
		}
		if failure := runVaultExpectingFailure(t, vault, home, h.ts.URL, token, "lease", "lookup", lease.LeaseID); !strings.Contains(string(failure), "invalid lease") {
			t.Fatalf("lookup of a revoked lease = %s", failure)
		}
	}
	if h.logContains(t, creds.Data["secret_key"]) || h.logContains(t, creds.Data["session_token"]) {
		t.Fatal("an STS secret reached the event log")
	}
	t.Logf("A203_AWS_OK creds=%s sts=%s arn=%s", creds.LeaseID, sts.LeaseID, creds.Data["arn"])
}

// TestServedVaultKubernetesCredentialsOnKind is A203 for Kubernetes against a
// real cluster (kind): the stock CLI writes kubernetes/creds/<role>, the token
// authenticates to the API server as the ServiceAccount the response names and
// reads what the bound ClusterRole allows, and `lease revoke -sync` returns once
// the ServiceAccount is gone, after which the API server refuses the token (once
// its authentication cache, 10 s by default, lets go of it). It runs when
// K8S_SERVER, K8S_ADMIN_TOKEN and K8S_CA_FILE name a cluster.
func TestServedVaultKubernetesCredentialsOnKind(t *testing.T) {
	server, adminToken, caFile := os.Getenv("K8S_SERVER"), os.Getenv("K8S_ADMIN_TOKEN"), os.Getenv("K8S_CA_FILE")
	if server == "" || adminToken == "" || caFile == "" {
		t.Skip("K8S_SERVER, K8S_ADMIN_TOKEN and K8S_CA_FILE name the cluster for this proof")
	}
	vault := vaultCLIBinary(t)
	ctx := context.Background()
	caPEM, err := os.ReadFile(caFile) // #nosec G304 G703 -- test reads the cluster CA its runner wrote (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := mtls.HTTPTransport(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	cluster := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	kube := func(method, path, bearer string, body any) (int, []byte) {
		t.Helper()
		var reader io.Reader
		if body != nil {
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			reader = bytes.NewReader(raw)
		}
		req, err := http.NewRequestWithContext(ctx, method, server+path, reader) // #nosec G704 -- test calls the cluster its runner named (CWE-918)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("Content-Type", "application/json")
		resp, err := cluster.Do(req) // #nosec G704 -- test calls the cluster its runner named (CWE-918)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, raw
	}
	namespace := "trstctl-a203-" + strings.ToLower(time.Now().UTC().Format("150405"))
	if status, body := kube(http.MethodPost, "/api/v1/namespaces", adminToken, map[string]any{
		"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": namespace},
	}); status != http.StatusCreated {
		t.Fatalf("create namespace: %d %s", status, body)
	}
	t.Cleanup(func() { kube(http.MethodDelete, "/api/v1/namespaces/"+namespace, adminToken, nil) })
	// The API server's own audience, from its discovery document.
	status, body := kube(http.MethodGet, "/.well-known/openid-configuration", adminToken, nil)
	var discovery struct{ Issuer string }
	if status != http.StatusOK || json.Unmarshal(body, &discovery) != nil || discovery.Issuer == "" {
		t.Fatalf("service-account issuer discovery: %d %s", status, body)
	}

	registry, err := dynamicSecretProvidersFromConfig(ctx, []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "apps-k8s", Type: "kubernetes", Endpoint: server, Namespace: namespace,
		KubernetesAudience: discovery.Issuer, BearerTokenRef: writeServedCredentialFile(t, "k8s-admin-token", adminToken),
		KubernetesTLSCARef: writeServedCredentialFile(t, "k8s-ca.pem", string(caPEM)),
		AllowPrivate:       true, PrivateEgressCIDRs: []string{"127.0.0.0/8"},
		AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "ClusterRole/view"}, MaxTTL: "1h",
		UsernamePrefix: "trstctl-a203",
	}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = registry
	})
	registerServedTenant(t, h, "Vault Kubernetes credentials tenant")
	startServedExternalCADispatcher(t, h)
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	home := t.TempDir()

	creds := decodeVaultLease(t, runVault(t, vault, home, h.ts.URL, token,
		"write", "-format=json", "kubernetes/creds/reader", "kubernetes_namespace="+namespace, "ttl=20m"))
	name, saToken := creds.Data["service_account_name"], creds.Data["service_account_token"]
	if !strings.HasPrefix(creds.LeaseID, "kubernetes/creds/reader/lease-") || creds.Renewable || creds.LeaseDuration < 1190 ||
		name == "" || saToken == "" || creds.Data["service_account_namespace"] != namespace {
		t.Fatalf("kubernetes/creds write = lease %s renewable %v duration %d name %q namespace %q", creds.LeaseID, creds.Renewable, creds.LeaseDuration, name, creds.Data["service_account_namespace"])
	}
	status, body = kube(http.MethodPost, "/apis/authentication.k8s.io/v1/selfsubjectreviews", saToken, map[string]any{
		"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview",
	})
	var review struct {
		Status struct {
			UserInfo struct{ Username string } `json:"userInfo"`
		} `json:"status"`
	}
	want := "system:serviceaccount:" + namespace + ":" + name
	if status != http.StatusCreated || json.Unmarshal(body, &review) != nil || review.Status.UserInfo.Username != want {
		t.Fatalf("SelfSubjectReview as the leased token = %d %s, want %s", status, body, want)
	}
	if status, body := kube(http.MethodGet, "/api/v1/namespaces/"+namespace+"/configmaps", saToken, nil); status != http.StatusOK {
		t.Fatalf("the view binding does not let the token list configmaps: %d %s", status, body)
	}
	if status, _ := kube(http.MethodGet, "/api/v1/namespaces/"+namespace+"/serviceaccounts/"+name, adminToken, nil); status != http.StatusOK {
		t.Fatalf("the cluster does not have ServiceAccount %s: %d", name, status)
	}
	failure := runVaultExpectingFailure(t, vault, home, h.ts.URL, token, "lease", "renew", creds.LeaseID)
	if !strings.Contains(string(failure), "lease is not renewable") {
		t.Fatalf("renew of a Kubernetes lease = %s", failure)
	}
	failure = runVaultExpectingFailure(t, vault, home, h.ts.URL, token, "write", "kubernetes/creds/reader", "kubernetes_namespace=kube-system")
	if !strings.Contains(string(failure), "not this role's namespace") {
		t.Fatalf("another namespace = %s", failure)
	}

	if out := runVault(t, vault, home, h.ts.URL, token, "lease", "revoke", "-sync", creds.LeaseID); !strings.Contains(string(out), "Success! Revoked lease") {
		t.Fatalf("lease revoke -sync = %s", out)
	}
	if status, body := kube(http.MethodGet, "/api/v1/namespaces/"+namespace+"/serviceaccounts/"+name, adminToken, nil); status != http.StatusNotFound {
		t.Fatalf("ServiceAccount %s after revoke = %d %s, want 404", name, status, body)
	}
	// The API server caches a successful token authentication (10 s by
	// default), so the refusal can trail the deletion by that long.
	revokedAt := time.Now()
	for {
		status, body := kube(http.MethodPost, "/apis/authentication.k8s.io/v1/selfsubjectreviews", saToken, map[string]any{
			"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview",
		})
		if status == http.StatusUnauthorized {
			break
		}
		if time.Since(revokedAt) > 30*time.Second {
			t.Fatalf("the revoked token still authenticates 30 s after revocation: %d %s", status, body)
		}
		time.Sleep(500 * time.Millisecond)
	}
	refusedAfter := time.Since(revokedAt).Round(100 * time.Millisecond)
	if h.logContains(t, saToken) {
		t.Fatal("the ServiceAccount token reached the event log")
	}
	t.Logf("A203_KUBERNETES_OK lease=%s serviceaccount=%s/%s token refused %s after revoke", creds.LeaseID, namespace, name, refusedAfter)
}
