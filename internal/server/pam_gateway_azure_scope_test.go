// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"net/url"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/config"
)

func TestAzureGatewayProviderCopiesOAuthAuthorityBeforeReview(t *testing.T) {
	cfg := config.DynamicSecretProviderConfig{ID: "owned-azure", TenantID: servedTestTenant, Type: "azure-entra", ApplicationClient: a263AzureClient, AzureTenant: a263AzureTenant, Gateway: &config.DynamicSecretGatewayConfig{Endpoint: "https://graph.microsoft.com", TokenEndpoint: (&url.URL{Scheme: "https", Host: "login.microsoftonline.com", Path: a263AzureTokenPath}).String(), Scopes: []string{a263AzureScope}}}
	provider := newConfiguredDynamicProvider(cfg, map[string]bool{"reader": true}, time.Hour, integrationCredentialResolver{}, nil).(*configuredDynamicProvider)
	revision := provider.DynamicSecretConfigurationRevision()
	cfg.Gateway.Endpoint = "https://different.example"
	cfg.Gateway.TokenEndpoint = "https://different.example/token"
	cfg.Gateway.Scopes[0] = "https://www.googleapis.com/auth/cloud-platform"
	endpoint, scopes, subject, err := provider.DynamicSecretGatewayOAuth()
	if err != nil || endpoint != (&url.URL{Scheme: "https", Host: "login.microsoftonline.com", Path: a263AzureTokenPath}).String() || len(scopes) != 1 || scopes[0] != a263AzureScope || subject != a263AzureClient {
		t.Fatal("caller changed reviewed OAuth authority")
	}
	scopes[0] = "https://different.example/scope"
	_, scopes, _, _ = provider.DynamicSecretGatewayOAuth()
	if scopes[0] != a263AzureScope {
		t.Fatal("returned slice changed reviewed OAuth authority")
	}
	origin, _, _, err := provider.DynamicSecretGatewayUpstream(context.Background())
	if err != nil || origin != "https://graph.microsoft.com" || provider.DynamicSecretConfigurationRevision() != revision {
		t.Fatal("caller changed reviewed API origin")
	}
}
