// SPDX-License-Identifier: BUSL-1.1

package authmethod

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestCR243AzureIssuerTenantParserRejectsSharedOrAmbiguousIssuers(t *testing.T) {
	const tenant = "22222222-2222-2222-2222-222222222222"
	for _, tt := range []struct {
		issuer string
		want   string
	}{
		{"https://login.microsoftonline.com/" + tenant + "/v2.0", tenant},
		{"https://sts.windows.net/" + tenant + "/", tenant},
		{"https://login.microsoftonline.com/common/v2.0", ""},
		{"https://login.microsoftonline.com/organizations/v2.0", ""},
		{"https://login.microsoftonline.com/" + tenant + "/v2.0/extra", ""},
		{"https://user@login.microsoftonline.com/" + tenant + "/v2.0", ""},
		{"https://login.microsoftonline.com/" + tenant + "/v2.0?next=foreign", ""},
		{"http://login.microsoftonline.com/" + tenant + "/v2.0", ""},
	} {
		if got := AzureTenantFromIssuer(tt.issuer); got != tt.want {
			t.Errorf("AzureTenantFromIssuer(%q) = %q, want %q", tt.issuer, got, tt.want)
		}
	}
}

func TestCR243MachineVerifiersRefuseMissingIssuerOrCloudBoundary(t *testing.T) {
	f := newOIDCFixture(t)
	claims := map[string]any{
		"iss": "https://issuer.example", "aud": "trstctl", "sub": "workload-1",
		"exp": f.now.Add(time.Hour).Unix(), "tenant_id": "tenant-a",
		"oid":    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		"tid":    "22222222-2222-2222-2222-222222222222",
		"google": map[string]any{"compute_engine": map[string]any{"instance_id": "4242", "project_id": "foreign-project"}},
		"kubernetes.io": map[string]any{
			"namespace": "payments", "serviceaccount": map[string]any{"name": "api", "uid": "sa-1"},
			"pod": map[string]any{"name": "api-1", "uid": "pod-1"},
		},
	}
	credential := f.sign(t, claims)
	for _, tt := range []struct {
		name   string
		method Method
		want   string
	}{
		{"oidc", OIDCMethod{JWKS: f.jwks, Audience: "trstctl", TenantID: "tenant-a", TenantClaim: "tenant_id", Scopes: []string{"secrets:read"}, Now: func() time.Time { return f.now }}, "issuer"},
		{"jwt", JWTMethod{JWKS: f.jwks, Audience: "trstctl", TenantID: "tenant-a", TenantClaim: "tenant_id", Scopes: []string{"secrets:read"}, Now: func() time.Time { return f.now }}, "issuer"},
		{"kubernetes", KubernetesSATMethod{JWKS: f.jwks, Audience: "trstctl", TenantID: "tenant-a", TenantClaim: "tenant_id", Scopes: []string{"secrets:read"}, Now: func() time.Time { return f.now }}, "issuer"},
		{"gcp", GCPMethod{JWKS: f.jwks, Issuer: "https://issuer.example", Audience: "trstctl", TenantID: "tenant-a", TenantClaim: "tenant_id", Scopes: []string{"secrets:read"}, Now: func() time.Time { return f.now }}, "allowed_projects"},
		{"azure", AzureMethod{JWKS: f.jwks, Issuer: "https://issuer.example", Audience: "trstctl", TenantID: "tenant-a", TenantClaim: "tenant_id", Scopes: []string{"secrets:read"}, Now: func() time.Time { return f.now }}, "tenant"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := tt.method.Authenticate(context.Background(), credential)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("unbound %s method error = %v, want %q", tt.name, err, tt.want)
			}
		})
	}
}

func TestCR243AzureTenantIssuerAlsoBindsSignedTID(t *testing.T) {
	f := newOIDCFixture(t)
	const tenant = "22222222-2222-2222-2222-222222222222"
	issuer := "https://login.microsoftonline.com/" + tenant + "/v2.0"
	method := AzureMethod{JWKS: f.jwks, Issuer: issuer, Audience: "trstctl",
		TenantID: "tenant-a", TenantClaim: "tenant_id", Scopes: []string{"secrets:read"},
		Now: func() time.Time { return f.now }}
	claims := map[string]any{
		"iss": issuer, "aud": "trstctl", "sub": "workload-1", "oid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		"tenant_id": "tenant-a", "tid": tenant, "exp": f.now.Add(time.Hour).Unix(),
	}
	if _, scopes, err := method.Authenticate(context.Background(), f.sign(t, claims)); err != nil || len(scopes) != 1 || scopes[0] != "secrets:read" {
		t.Fatalf("tenant-specific issuer rejected matching tid: scopes=%v err=%v", scopes, err)
	}
	claims["tid"] = "33333333-3333-3333-3333-333333333333"
	if _, _, err := method.Authenticate(context.Background(), f.sign(t, claims)); err == nil || !strings.Contains(err.Error(), "tid") {
		t.Fatalf("tenant-specific issuer accepted foreign tid: %v", err)
	}
}
