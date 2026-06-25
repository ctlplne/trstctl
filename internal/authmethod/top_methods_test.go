package authmethod

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestTopMachineAuthMethodsAuthenticate(t *testing.T) {
	f := newOIDCFixture(t)
	baseClaims := map[string]any{
		"iss":       "https://issuer.example",
		"aud":       "trstctl",
		"sub":       "workload-1",
		"exp":       f.now.Add(time.Hour).Unix(),
		"tenant_id": "tenant-a",
		"scopes":    []string{"secrets:read"},
	}
	for name, method := range map[string]Method{
		"oidc": OIDCMethod{
			JWKS: f.jwks, Issuer: "https://issuer.example", Audience: "trstctl",
			TenantID: "tenant-a", TenantClaim: "tenant_id", Now: func() time.Time { return f.now },
		},
		"jwt": JWTMethod{
			JWKS: f.jwks, Issuer: "https://issuer.example", Audience: "trstctl",
			TenantID: "tenant-a", TenantClaim: "tenant_id", Now: func() time.Time { return f.now },
		},
	} {
		principal, scopes, err := method.Authenticate(context.Background(), f.sign(t, baseClaims))
		if err != nil {
			t.Fatalf("%s authenticate: %v", name, err)
		}
		if principal != "workload-1" || len(scopes) != 1 || scopes[0] != "secrets:read" {
			t.Fatalf("%s principal/scopes = %q/%v", name, principal, scopes)
		}
	}

	k8sClaims := cloneClaims(baseClaims)
	k8sClaims["sub"] = "system:serviceaccount:payments:api"
	k8sClaims["kubernetes.io"] = map[string]any{
		"namespace": "payments",
		"serviceaccount": map[string]any{
			"name": "api",
			"uid":  "sa-1",
		},
		"pod": map[string]any{"name": "api-abc", "uid": "pod-1"},
	}
	k8s := KubernetesSATMethod{
		JWKS: f.jwks, Issuer: "https://issuer.example", Audience: "trstctl",
		TenantID: "tenant-a", TenantClaim: "tenant_id",
		AllowedNamespaces:      map[string]bool{"payments": true},
		AllowedServiceAccounts: map[string]bool{"payments/api": true},
		Now:                    func() time.Time { return f.now },
	}
	principal, _, err := k8s.Authenticate(context.Background(), f.sign(t, k8sClaims))
	if err != nil {
		t.Fatalf("kubernetes authenticate: %v", err)
	}
	if principal != "system:serviceaccount:payments:api" {
		t.Fatalf("kubernetes principal = %q", principal)
	}

	gcpClaims := cloneClaims(baseClaims)
	gcpClaims["google"] = map[string]any{
		"compute_engine": map[string]any{
			"instance_id":   "987654321",
			"project_id":    "proj-a",
			"zone":          "us-central1-a",
			"instance_name": "web-1",
		},
	}
	gcp := GCPMethod{
		JWKS: f.jwks, Issuer: "https://issuer.example", Audience: "trstctl",
		TenantID: "tenant-a", TenantClaim: "tenant_id",
		AllowedProjects: map[string]bool{"proj-a": true},
		Now:             func() time.Time { return f.now },
	}
	principal, _, err = gcp.Authenticate(context.Background(), f.sign(t, gcpClaims))
	if err != nil {
		t.Fatalf("gcp authenticate: %v", err)
	}
	if principal != "gcp:proj-a/987654321" {
		t.Fatalf("gcp principal = %q", principal)
	}

	azureClaims := cloneClaims(baseClaims)
	azureClaims["oid"] = "00000000-0000-0000-0000-000000000001"
	azureClaims["tid"] = "azure-tenant-a"
	azure := AzureMethod{
		JWKS: f.jwks, Issuer: "https://issuer.example", Audience: "trstctl",
		TenantID: "tenant-a", TenantClaim: "tenant_id",
		AllowedAzureTenants: map[string]bool{"azure-tenant-a": true},
		Now:                 func() time.Time { return f.now },
	}
	principal, _, err = azure.Authenticate(context.Background(), f.sign(t, azureClaims))
	if err != nil {
		t.Fatalf("azure authenticate: %v", err)
	}
	if principal != "azure:00000000-0000-0000-0000-000000000001" {
		t.Fatalf("azure principal = %q", principal)
	}

	aws := AWSIAMMethod{
		TenantID: "tenant-a",
		Client: fakeSTSClient{identity: AWSIdentity{
			Account: "123456789012",
			ARN:     "arn:aws:sts::123456789012:assumed-role/web/i-1",
			UserID:  "AROATEST:web",
		}},
		AllowedAccounts: map[string]bool{"123456789012": true},
		Scopes:          []string{"secrets:read"},
	}
	principal, scopes, err := aws.Authenticate(context.Background(), []byte(`{"signed":true}`))
	if err != nil {
		t.Fatalf("aws authenticate: %v", err)
	}
	if principal != "arn:aws:sts::123456789012:assumed-role/web/i-1" || len(scopes) != 1 || scopes[0] != "secrets:read" {
		t.Fatalf("aws principal/scopes = %q/%v", principal, scopes)
	}

	badTenant := cloneClaims(baseClaims)
	badTenant["tenant_id"] = "tenant-b"
	if _, _, err := k8s.Authenticate(context.Background(), f.sign(t, badTenant)); err == nil {
		t.Fatal("kubernetes accepted a JWT bound to another tenant")
	}
}

type fakeSTSClient struct {
	identity AWSIdentity
}

func (f fakeSTSClient) GetCallerIdentity(_ context.Context, credential []byte) (AWSIdentity, error) {
	if len(credential) == 0 {
		return AWSIdentity{}, fmt.Errorf("empty credential")
	}
	return f.identity, nil
}

func cloneClaims(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
