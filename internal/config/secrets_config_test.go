package config_test

import (
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
	env := map[string]string{
		"TRSTCTL_POSTGRES_MODE":    "external",
		"TRSTCTL_POSTGRES_DSN":     "postgres://u:p@h:5432/db?sslmode=require",
		"TRSTCTL_NATS_MODE":        "external",
		"TRSTCTL_NATS_URL":         "nats://h:4222",
		"TRSTCTL_SECRETS_KEK_FILE": "/etc/trstctl/kek.bin",
	}
	cfg, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Secrets.KEKFile != "/etc/trstctl/kek.bin" {
		t.Errorf("secrets.kek_file = %q, want the env override", cfg.Secrets.KEKFile)
	}
}
