// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/accessdesktop"
	"trstctl.com/trstctl/internal/config"
)

func TestDesktopReviewedRouteCannotChangeThroughConfigurationAliases(t *testing.T) {
	cfg := config.DynamicSecretProviderConfig{Type: "unix", AllowStaticRotation: true, Desktop: &accessdesktop.Binding{Address: "host.example:3389", CertificateSHA256: strings.Repeat("ab", 32), Width: 800, Height: 600}}
	provider := newConfiguredDynamicProvider(cfg, nil, time.Minute, integrationCredentialResolver{}, nil).(*configuredDynamicProvider)
	cfg.Desktop.Address = "foreign.example:3389"
	a, err := provider.DynamicSecretGatewayDesktop()
	if err != nil || a.Address != "host.example:3389" {
		t.Fatal("reviewed desktop route changed through caller alias")
	}
	a.Address = "another.example:3389"
	b, err := provider.DynamicSecretGatewayDesktop()
	if err != nil || b.Address != "host.example:3389" {
		t.Fatal("returned route mutated the reviewed authority")
	}
}
