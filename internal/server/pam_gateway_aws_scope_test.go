// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/config"
)

func TestAWSGatewayProviderCopiesPublicRoutingBeforeReview(t *testing.T) {
	cfg := config.DynamicSecretProviderConfig{ID: "owned-sts", TenantID: servedTestTenant, Type: "aws-sts", Gateway: &config.DynamicSecretGatewayConfig{Endpoint: "https://s3.us-east-1.amazonaws.com", Service: "s3", Region: "us-east-1"}}
	provider := newConfiguredDynamicProvider(cfg, map[string]bool{"reader": true}, time.Hour, integrationCredentialResolver{}, nil).(*configuredDynamicProvider)
	revision := provider.DynamicSecretConfigurationRevision()
	cfg.Gateway.Endpoint = "https://different.example"
	cfg.Gateway.Service = "sts"
	cfg.Gateway.Region = "us-west-2"
	service, region, err := provider.DynamicSecretGatewayAWS()
	if err != nil || service != "s3" || region != "us-east-1" {
		t.Fatal("caller config mutation changed reviewed signing scope")
	}
	endpoint, _, _, err := provider.DynamicSecretGatewayUpstream(context.Background())
	if err != nil || endpoint != "https://s3.us-east-1.amazonaws.com" || provider.DynamicSecretConfigurationRevision() != revision {
		t.Fatal("caller mutation changed reviewed gateway endpoint")
	}
}
