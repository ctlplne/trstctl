// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/dynsecret"
)

// N3 against a stock IAM and STS API: an AWS STS provider with
// revoke_with_deny_policy ends a revoked lease's session through its role.
// Each revoked session gets its own inline deny policy on the role, read back
// before the revocation completes; the role's denial of an expired session is
// pruned by the next revocation, and its other policies are left alone. A
// provider without the opt-in leaves the session pending until its expiry.
// LocalStack's IAM stores and returns the policies but does not enforce them,
// so AWS's enforcement of the denial stays a live proof.
func TestServedSTSRevocationDeniesTheSessionThroughItsRoleN3(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required: %v", err)
	}
	if out, err := exec.Command("docker", "image", "inspect", a202LocalStackImage).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Skipf("the pinned LocalStack image is not present locally: %v\n%s", err, out)
	}
	localstack, address := a201Container(t, "4566", "-e", "SERVICES=iam,sts", a202LocalStackImage)
	endpoint := "http://" + address
	a201Await(t, "LocalStack IAM and STS", func() bool {
		resp, err := http.Get(endpoint + "/_localstack/health")
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		var health struct{ Services map[string]string }
		return json.NewDecoder(resp.Body).Decode(&health) == nil &&
			(health.Services["iam"] == "available" || health.Services["iam"] == "running") &&
			(health.Services["sts"] == "available" || health.Services["sts"] == "running")
	})
	awslocal := func(args ...string) string {
		t.Helper()
		out, err := a201Exec(localstack, append([]string{"awslocal"}, args...)...)
		if err != nil {
			t.Fatalf("awslocal %v: %v %s", args, err, out)
		}
		return out
	}
	const role = "n3-deployer"
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}]}`
	allow := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::n3-artifacts/*"}]}`
	staleDenial := "trstctl-revoked-1000000000-0123456789ab"
	awslocal("iam", "create-role", "--role-name", role, "--assume-role-policy-document", trust)
	awslocal("iam", "put-role-policy", "--role-name", role, "--policy-name", "n3-app-inline", "--policy-document", allow)
	awslocal("iam", "put-role-policy", "--role-name", role, "--policy-name", staleDenial, "--policy-document",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"StringEquals":{"aws:userid":"AROAOLD:expired-session"}}}]}`)
	rolePolicies := func() []string {
		t.Helper()
		var listed struct{ PolicyNames []string }
		if err := json.Unmarshal([]byte(awslocal("iam", "list-role-policies", "--role-name", role)), &listed); err != nil {
			t.Fatal(err)
		}
		slices.Sort(listed.PolicyNames)
		return listed.PolicyNames
	}

	roleARN := "arn:aws:iam::000000000000:role/" + role
	provider := func(id string, deny bool) config.DynamicSecretProviderConfig {
		return config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: id, Type: "aws-sts", Endpoint: endpoint, IAMEndpoint: endpoint,
			AllowInsecureLoopback: true, Region: "us-east-1", AccessKeyID: "test",
			SecretAccessRef: writeServedCredentialFile(t, "aws-secret-"+id, "test"),
			AllowedRoles:    []string{"deployer"}, RoleBindings: map[string]string{"deployer": roleARN}, MaxTTL: "1h",
			RevokeWithDenyPolicy: deny,
		}
	}
	configs := []config.DynamicSecretProviderConfig{provider("aws-deny", true), provider("aws-ttl", false)}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: configs}, true); err != nil {
		t.Fatalf("the providers as configured: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), configs, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnableSecretsAPI = true
		d.TenantDynamicSecretProviders = registry
		d.DynamicSecretAccessInterval = time.Hour
	})
	startServedExternalCADispatcher(t, h)
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "n3-operator", "secrets:read", "secrets:write")

	// The catalog says how each provider's revocation ends a session.
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/providers", tok, nil)
	var catalog struct {
		Configured []struct {
			ID         string `json:"id"`
			Revocation string `json:"revocation"`
		} `json:"configured_providers"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &catalog) != nil {
		t.Fatalf("provider catalog: %d %s", status, body)
	}
	revocation := map[string]string{}
	for _, p := range catalog.Configured {
		revocation[p.ID] = p.Revocation
	}
	if revocation["aws-deny"] != dynsecret.RevocationMethodDenyPolicy || revocation["aws-ttl"] != "ttl_only" {
		t.Fatalf("configured revocation = %v", revocation)
	}

	type leaseView struct {
		dynamicLeaseView
		NativeExpiresAt  *time.Time `json:"native_expires_at"`
		RevocationMethod string     `json:"revocation_method"`
	}
	revoke := func(leaseID string) {
		t.Helper()
		if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases/"+leaseID+"/revoke", tok, "n3-revoke-"+leaseID, map[string]any{}); status != http.StatusOK && status != http.StatusAccepted {
			t.Fatalf("revoke %s: %d %s", leaseID, status, body)
		}
	}
	completed := func(leaseID string) leaseView {
		t.Helper()
		var lease leaseView
		for deadline := time.Now().Add(30 * time.Second); ; {
			status, body := secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+leaseID, tok, nil)
			if status == http.StatusOK && json.Unmarshal(body, &lease) == nil && lease.RevocationStatus == "completed" {
				return lease
			}
			if time.Now().After(deadline) {
				t.Fatalf("the revocation of %s did not complete: %d %s", leaseID, status, body)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	session := func(leaseID string) (assumedRoleID string, expiration time.Time) {
		t.Helper()
		record, err := h.store.GetDynamicSecretLease(context.Background(), h.tenant, leaseID)
		if err != nil {
			t.Fatal(err)
		}
		var ref struct {
			AssumedRoleID string    `json:"assumed_role_id"`
			Expiration    time.Time `json:"expiration"`
		}
		if err := json.Unmarshal([]byte(record.BackendRef), &ref); err != nil || ref.AssumedRoleID == "" {
			t.Fatalf("lease %s session reference: %v", leaseID, err)
		}
		return ref.AssumedRoleID, ref.Expiration
	}
	denial := func(assumedRoleID string, expiration time.Time) string {
		t.Helper()
		name := dynsecret.AWSSTSDenyPolicyName(assumedRoleID, expiration)
		var got struct {
			PolicyDocument json.RawMessage
		}
		if err := json.Unmarshal([]byte(awslocal("iam", "get-role-policy", "--role-name", role, "--policy-name", name)), &got); err != nil {
			t.Fatal(err)
		}
		doc := string(got.PolicyDocument)
		var asString string
		if json.Unmarshal(got.PolicyDocument, &asString) == nil {
			if decoded, err := url.PathUnescape(asString); err == nil {
				asString = decoded
			}
			doc = asString
		}
		var policy struct {
			Statement []struct {
				Effect    string
				Action    string
				Resource  string
				Condition map[string]map[string]string
			}
		}
		if err := json.Unmarshal([]byte(doc), &policy); err != nil || len(policy.Statement) != 1 {
			t.Fatalf("policy %s = %s (%v)", name, doc, err)
		}
		if s := policy.Statement[0]; s.Effect != "Deny" || s.Action != "*" || s.Resource != "*" || s.Condition["StringEquals"]["aws:userid"] != assumedRoleID {
			t.Fatalf("policy %s statement = %+v", name, s)
		}
		return name
	}

	// Two sessions of one role revoked: each is denied by its own policy.
	first, firstCredential := issueG2Lease(t, h, tok, "n3-first", "aws-deny", "deployer")
	second, _ := issueG2Lease(t, h, tok, "n3-second", "aws-deny", "deployer")
	revoke(first)
	if lease := completed(first); lease.RevocationMethod != dynsecret.RevocationMethodDenyPolicy || lease.NativeExpiresAt == nil || !time.Now().Before(*lease.NativeExpiresAt) {
		t.Fatalf("first revoked lease = %+v", lease)
	}
	firstID, firstExpiry := session(first)
	firstDenial := denial(firstID, firstExpiry)
	if got := rolePolicies(); slices.Contains(got, staleDenial) || !slices.Contains(got, "n3-app-inline") || !slices.Contains(got, firstDenial) {
		t.Fatalf("role policies after the first revocation = %v (the stale denial pruned, the app policy kept)", got)
	}
	revoke(second)
	if lease := completed(second); lease.RevocationMethod != dynsecret.RevocationMethodDenyPolicy {
		t.Fatalf("second revoked lease = %+v", lease)
	}
	secondID, secondExpiry := session(second)
	secondDenial := denial(secondID, secondExpiry)
	if got, want := rolePolicies(), []string{"n3-app-inline", firstDenial, secondDenial}; !slices.Equal(got, sortedCopy(want)) {
		t.Fatalf("role policies = %v, want %v", got, sortedCopy(want))
	}

	// Without the opt-in the session lapses at its expiry: the revocation
	// stays pending and nothing is written to the role.
	ttl, _ := issueG2Lease(t, h, tok, "n3-ttl", "aws-ttl", "deployer")
	revoke(ttl)
	time.Sleep(2 * time.Second) // the dispatcher has had its turns
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/leases/"+ttl, tok, nil)
	var pending leaseView
	if status != http.StatusOK || json.Unmarshal(body, &pending) != nil || pending.RevocationStatus != "pending" || pending.RevocationMethod != "" || pending.NativeExpiresAt == nil {
		t.Fatalf("the TTL-only revocation: %d %s", status, body)
	}
	if got := rolePolicies(); len(got) != 3 {
		t.Fatalf("a TTL-only revocation wrote to the role: %v", got)
	}
	if strings.Contains(string(body), firstCredential) || h.logContains(t, firstCredential) {
		t.Fatal("the session credential reached a lease read or the event log")
	}
	t.Logf("N3_LOCALSTACK_OK first=%s denial=%s second=%s denial=%s ttl_pending=%s", first, firstDenial, second, secondDenial, ttl)
}

func sortedCopy(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}
