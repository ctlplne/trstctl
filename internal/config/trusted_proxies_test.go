// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"slices"
	"strings"
	"testing"
)

// TestServerTrustedProxiesM1L1: TRSTCTL_SERVER_TRUSTED_PROXIES (or
// server.trusted_proxies) names the load balancers whose X-Forwarded-For is
// read; a prefix matching every address, or one that is not a network, fails
// validation, and none is the default.
func TestServerTrustedProxiesM1L1(t *testing.T) {
	cfg, err := Load(func(k string) string {
		return map[string]string{"TRSTCTL_SERVER_TRUSTED_PROXIES": "10.0.0.0/8, 192.0.2.7"}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.Server.TrustedProxies, []string{"10.0.0.0/8", "192.0.2.7"}) {
		t.Fatalf("trusted proxies = %q", cfg.Server.TrustedProxies)
	}
	if errs := validateServerConfig(cfg); len(errs) != 0 {
		t.Fatalf("valid trusted proxies refused: %v", errs)
	}
	for _, bad := range []string{"0.0.0.0/0", "::/0", "the-load-balancer"} {
		cfg.Server.TrustedProxies = []string{bad}
		errs := validateServerConfig(cfg)
		if len(errs) == 0 || !strings.Contains(errs[len(errs)-1].Error(), "server.trusted_proxies") {
			t.Errorf("server.trusted_proxies %q accepted (%v)", bad, errs)
		}
	}
	plain, err := Load(func(string) string { return "" })
	if err != nil || len(plain.Server.TrustedProxies) != 0 {
		t.Fatalf("default trusted proxies = %q, %v", plain.Server.TrustedProxies, err)
	}
}
