// SPDX-License-Identifier: BUSL-1.1

package config_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// TestSecretsKEKDefault: the KEK file has a sensible default under the data dir so
// single-node eval provisions one automatically.
func TestSecretsKEKDefault(t *testing.T) {
	if config.Default().Secrets.KEKFile == "" {
		t.Error("secrets.kek_file should have a default path")
	}
}

// TestSecretsKEKEnvOverride: operators point the KEK at their own (HSM-exported or
// managed) key file via the environment.
func TestSecretsKEKEnvOverride(t *testing.T) {
	env := map[string]string{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		"TRSTCTL_POSTGRES_MODE":                       "external",
		"TRSTCTL_POSTGRES_DSN":                        "postgres://u:p@h:5432/db?sslmode=require",
		"TRSTCTL_NATS_MODE":                           "external",
		"TRSTCTL_NATS_URL":                            "nats://h:4222",
		"TRSTCTL_SIGNER_AUTH_TOKEN_COMMAND":           "/usr/local/bin/trstctl-sign-approve",
		"TRSTCTL_SIGNER_ALLOW_CO_RESIDENT_AUTHORIZER": "false",
		"TRSTCTL_SECRETS_KEK_FILE":                    "/etc/trstctl/kek.bin",
	}
	cfg, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Secrets.KEKFile != "/etc/trstctl/kek.bin" {
		t.Errorf("secrets.kek_file = %q, want the env override", cfg.Secrets.KEKFile)
	}
}

func TestSecretsGitleaksEnvOverride(t *testing.T) {
	env := map[string]string{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		"TRSTCTL_POSTGRES_MODE":                       "external",
		"TRSTCTL_POSTGRES_DSN":                        "postgres://u:p@h:5432/db?sslmode=require",
		"TRSTCTL_NATS_MODE":                           "external",
		"TRSTCTL_NATS_URL":                            "nats://h:4222",
		"TRSTCTL_SIGNER_AUTH_TOKEN_COMMAND":           "/usr/local/bin/trstctl-sign-approve",
		"TRSTCTL_SIGNER_ALLOW_CO_RESIDENT_AUTHORIZER": "false",
		"TRSTCTL_SECRETS_GITLEAKS_BIN":                "/opt/trstctl/tools/gitleaks",
		"TRSTCTL_SECRETS_SCAN_ROOTS":                  "/workspace/repos,/workspace/rules",
	}
	cfg, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Secrets.GitleaksBin != "/opt/trstctl/tools/gitleaks" {
		t.Errorf("secrets.gitleaks_bin = %q, want the env override", cfg.Secrets.GitleaksBin)
	}
	if len(cfg.Secrets.ScanRoots) != 2 || cfg.Secrets.ScanRoots[0] != "/workspace/repos" || cfg.Secrets.ScanRoots[1] != "/workspace/rules" {
		t.Errorf("secrets.scan_roots = %#v, want the two configured roots", cfg.Secrets.ScanRoots)
	}
}

func TestBuiltinMachineTokenEnvOverride(t *testing.T) {
	env := map[string]string{ // #nosec G101 -- fabricated fixture path/identifiers; no credential value is present (CWE-798)
		"TRSTCTL_POSTGRES_MODE":                       "external",
		"TRSTCTL_POSTGRES_DSN":                        "postgres://u:p@h:5432/db?sslmode=require",
		"TRSTCTL_NATS_MODE":                           "external",
		"TRSTCTL_NATS_URL":                            "nats://h:4222",
		"TRSTCTL_SIGNER_AUTH_TOKEN_COMMAND":           "/usr/local/bin/trstctl-sign-approve",
		"TRSTCTL_SIGNER_ALLOW_CO_RESIDENT_AUTHORIZER": "false",
		"TRSTCTL_SECRETS_AUTH_SECRET_FILE":            "/run/secrets/machine-auth.bin",
		"TRSTCTL_SECRETS_AUTH_TOKEN_TENANT_ID":        "11111111-1111-1111-1111-111111111111",
		"TRSTCTL_SECRETS_AUTH_TOKEN_SCOPES":           "secrets:read,certs:read",
	}
	cfg, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Secrets.AuthTokenTenantID != env["TRSTCTL_SECRETS_AUTH_TOKEN_TENANT_ID"] {
		t.Fatalf("auth token tenant = %q", cfg.Secrets.AuthTokenTenantID)
	}
	if got := strings.Join(cfg.Secrets.AuthTokenScopes, ","); got != "secrets:read,certs:read" {
		t.Fatalf("auth token scopes = %q", got)
	}
}

func TestTenantSealLocalWrapperEnvOverride(t *testing.T) {
	env := map[string]string{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		"TRSTCTL_POSTGRES_MODE":                       "external",
		"TRSTCTL_POSTGRES_DSN":                        "postgres://u:p@h:5432/db?sslmode=require",
		"TRSTCTL_NATS_MODE":                           "external",
		"TRSTCTL_NATS_URL":                            "nats://h:4222",
		"TRSTCTL_SIGNER_AUTH_TOKEN_COMMAND":           "/usr/local/bin/trstctl-sign-approve",
		"TRSTCTL_SIGNER_ALLOW_CO_RESIDENT_AUTHORIZER": "false",
		"TRSTCTL_TENANT_SEAL_LOCAL_WRAPPER_ID":        "operator-a",
		"TRSTCTL_TENANT_SEAL_LOCAL_WRAPPER_FILE":      "/custody/operator-a.key",
		"TRSTCTL_IDEMPOTENCY_RESULT_FLEET_READY":      "true",
		"TRSTCTL_SECRET_ROTATION_HISTORY_FLEET_READY": "true",
	}
	cfg, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Secrets.TenantSealLocalWrappers) != 1 ||
		cfg.Secrets.TenantSealLocalWrappers[0] != (config.TenantSealLocalWrapper{
			ID: "operator-a", File: "/custody/operator-a.key",
		}) {
		t.Fatalf("tenant seal wrappers = %#v", cfg.Secrets.TenantSealLocalWrappers)
	}
	if !cfg.Secrets.IdempotencyResultFleetReady {
		t.Fatal("idempotency result fleet-ready assertion was not loaded")
	}
	if !cfg.Secrets.SecretRotationHistoryFleetReady {
		t.Fatal("secret-rotation history fleet-ready assertion was not loaded")
	}
}

func TestTenantSealLocalWrapperConfigFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		wrappers []config.TenantSealLocalWrapper
	}{
		{name: "missing id", wrappers: []config.TenantSealLocalWrapper{{File: "/key"}}},
		{name: "untrimmed id", wrappers: []config.TenantSealLocalWrapper{{ID: " a ", File: "/key"}}},
		{name: "missing file", wrappers: []config.TenantSealLocalWrapper{{ID: "a"}}},
		{name: "duplicate id", wrappers: []config.TenantSealLocalWrapper{{ID: "a", File: "/a"}, {ID: "a", File: "/b"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Secrets.TenantSealLocalWrappers = tc.wrappers
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate accepted invalid tenant-seal wrapper configuration")
			}
		})
	}
}
