// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"net/url"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/config"
)

func TestGCPGatewayProviderCopiesOAuthAuthorityBeforeReview(t *testing.T) {
	cfg := config.DynamicSecretProviderConfig{ID: "owned-gcp", TenantID: servedTestTenant, Type: "gcp-iam", ServiceAccount: a263GCPEmail, Gateway: &config.DynamicSecretGatewayConfig{Endpoint: "https://storage.googleapis.com", TokenEndpoint: (&url.URL{Scheme: "https", Host: "oauth2.googleapis.com", Path: "/token"}).String(), Scopes: []string{a263GCPScope}}}
	provider := newConfiguredDynamicProvider(cfg, map[string]bool{"reader": true}, time.Hour, integrationCredentialResolver{}, nil).(*configuredPreparedDynamicProvider)
	revision := provider.DynamicSecretConfigurationRevision()
	cfg.Gateway.Endpoint = "https://different.example"
	cfg.Gateway.TokenEndpoint = "https://different.example/token"
	cfg.Gateway.Scopes[0] = "https://www.googleapis.com/auth/cloud-platform"
	endpoint, scopes, subject, err := provider.DynamicSecretGatewayOAuth()
	if err != nil || endpoint != (&url.URL{Scheme: "https", Host: "oauth2.googleapis.com", Path: "/token"}).String() || len(scopes) != 1 || scopes[0] != a263GCPScope || subject != a263GCPEmail {
		t.Fatal("caller changed reviewed OAuth authority")
	}
	scopes[0] = "https://different.example/scope"
	_, scopes, _, _ = provider.DynamicSecretGatewayOAuth()
	if scopes[0] != a263GCPScope {
		t.Fatal("returned slice changed reviewed OAuth authority")
	}
	origin, _, _, err := provider.DynamicSecretGatewayUpstream(context.Background())
	if err != nil || origin != "https://storage.googleapis.com" || provider.DynamicSecretConfigurationRevision() != revision {
		t.Fatal("caller changed reviewed API origin")
	}
}
