// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"testing"
	"time"
	"trstctl.com/trstctl/internal/accessconsole"
	"trstctl.com/trstctl/internal/config"
)

func TestConsoleProviderCopiesPublicBindingBeforeReview(t *testing.T) {
	cfg := config.DynamicSecretProviderConfig{Type: "aws-sts", ID: "owned-console", TenantID: servedTestTenant, Console: &accessconsole.Binding{FederationEndpoint: "https://signin.aws.amazon.com/federation", Destination: "https://console.aws.amazon.com/"}}
	p := newConfiguredDynamicProvider(cfg, map[string]bool{"reader": true}, time.Hour, integrationCredentialResolver{}, nil).(*configuredDynamicProvider)
	revision := p.DynamicSecretConfigurationRevision()
	cfg.Console.FederationEndpoint = "https://foreign.example/federation"
	cfg.Console.Destination = "https://foreign.example/"
	b, err := p.DynamicSecretGatewayConsole()
	if err != nil || b.FederationEndpoint != "https://signin.aws.amazon.com/federation" || b.Destination != "https://console.aws.amazon.com/" || p.DynamicSecretConfigurationRevision() != revision {
		t.Fatal("caller changed reviewed console destinations")
	}
	b.Destination = "https://foreign.example/"
	again, err := p.DynamicSecretGatewayConsole()
	if err != nil || again.Destination != "https://console.aws.amazon.com/" {
		t.Fatal("returned binding changed reviewed destinations")
	}
}
