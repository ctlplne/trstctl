// SPDX-License-Identifier: MPL-2.0

package config

import "testing"

func fullABAC() ABAC {
	return ABAC{
		Enabled: true,
		Module: `package trstctl.abac
default deny := false
`,
		Environment: map[string]string{"change_window": "false"},
	}
}

func TestABACDisabledNeedsNoConfig(t *testing.T) {
	c := Default()
	c.Auth.ABAC = ABAC{Enabled: false}
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled ABAC must not fail validation: %v", err)
	}
}

func TestABACEnabledFailsClosedWithoutModule(t *testing.T) {
	c := Default()
	a := fullABAC()
	a.Module = ""
	c.Auth.ABAC = a
	if err := c.Validate(); err == nil {
		t.Fatal("enabled ABAC without a module must fail validation")
	}
}

func TestABACEnabledValidPasses(t *testing.T) {
	c := Default()
	c.Auth.ABAC = fullABAC()
	if err := c.Validate(); err != nil {
		t.Fatalf("fully configured ABAC must validate: %v", err)
	}
}

func TestABACEnvOverlaysModuleAndEnvironment(t *testing.T) {
	env := map[string]string{
		"TRSTCTL_AUTH_ABAC_ENABLED":     "true",
		"TRSTCTL_AUTH_ABAC_MODULE":      fullABAC().Module,
		"TRSTCTL_AUTH_ABAC_ENVIRONMENT": "change_window=true,region=us-east-1",
	}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load with ABAC env: %v", err)
	}
	if !cfg.Auth.ABAC.Enabled {
		t.Fatal("ABAC env did not enable the overlay")
	}
	if cfg.Auth.ABAC.Environment["change_window"] != "true" || cfg.Auth.ABAC.Environment["region"] != "us-east-1" {
		t.Fatalf("unexpected ABAC environment overlay: %#v", cfg.Auth.ABAC.Environment)
	}
}
