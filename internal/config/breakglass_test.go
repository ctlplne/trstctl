// SPDX-License-Identifier: MPL-2.0

package config

import "testing"

func fullBreakglass() Breakglass {
	return Breakglass{
		Enabled:       true,
		CACertFile:    "/etc/trstctl/breakglass-ca.der",
		PublicKeyFile: "/etc/trstctl/breakglass-public.der",
	}
}

func TestBreakglassDisabledNeedsNoConfig(t *testing.T) {
	c := Default()
	c.Breakglass = Breakglass{Enabled: false}
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled break-glass must not fail validation: %v", err)
	}
}

func TestBreakglassEnabledRequiresVerifierMaterial(t *testing.T) {
	c := Default()
	c.Breakglass = Breakglass{Enabled: true}
	if err := c.Validate(); err == nil {
		t.Fatal("enabled break-glass without verifier material must fail validation")
	}
}

func TestBreakglassEnabledValidPasses(t *testing.T) {
	c := Default()
	c.Breakglass = fullBreakglass()
	if err := c.Validate(); err != nil {
		t.Fatalf("fully configured break-glass must validate: %v", err)
	}
}

func TestBreakglassEnvOverlaysVerifierMaterial(t *testing.T) {
	env := map[string]string{
		"TRSTCTL_BREAKGLASS_ENABLED":         "true",
		"TRSTCTL_BREAKGLASS_CA_CERT_FILE":    "/cfg/bg-ca.pem",
		"TRSTCTL_BREAKGLASS_PUBLIC_KEY_FILE": "/cfg/bg-pub.pem",
	}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load with break-glass env: %v", err)
	}
	if !cfg.Breakglass.Enabled {
		t.Fatal("break-glass env did not enable reconciliation")
	}
	if cfg.Breakglass.CACertFile != "/cfg/bg-ca.pem" || cfg.Breakglass.PublicKeyFile != "/cfg/bg-pub.pem" {
		t.Fatalf("unexpected break-glass verifier overlay: %#v", cfg.Breakglass)
	}
}
