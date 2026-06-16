package config_test

import (
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// TestMigrateAutoDefaultsOn: automatic migration ships on, so the single-node
// eval path and first boot apply the schema without extra steps.
func TestMigrateAutoDefaultsOn(t *testing.T) {
	if !config.Default().Migrate.Auto {
		t.Error("migrate.auto should default to on")
	}
}

// TestMigrateAutoEnvOverride: an operator can disable silent auto-migration (the
// pre-migration backup gate) from the environment. With it off, the config is
// still valid — boot fails later, with guidance, only when migrations are
// actually pending.
func TestMigrateAutoEnvOverride(t *testing.T) {
	env := map[string]string{
		"TRSTCTL_POSTGRES_MODE": "external",
		"TRSTCTL_POSTGRES_DSN":  "postgres://u:p@h:5432/db?sslmode=require",
		"TRSTCTL_NATS_MODE":     "external",
		"TRSTCTL_NATS_URL":      "nats://h:4222",
		"TRSTCTL_MIGRATE_AUTO":  "false",
	}
	cfg, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Migrate.Auto {
		t.Error("TRSTCTL_MIGRATE_AUTO=false should disable automatic migration")
	}
}

// TestMigrateAutoMalformedEnvIgnored: a typo cannot silently flip the gate; the
// prior (default-on) value stands.
func TestMigrateAutoMalformedEnvIgnored(t *testing.T) {
	env := map[string]string{
		"TRSTCTL_POSTGRES_MODE": "external",
		"TRSTCTL_POSTGRES_DSN":  "postgres://u:p@h:5432/db?sslmode=require",
		"TRSTCTL_NATS_MODE":     "external",
		"TRSTCTL_NATS_URL":      "nats://h:4222",
		"TRSTCTL_MIGRATE_AUTO":  "yep",
	}
	cfg, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Migrate.Auto {
		t.Error("a malformed TRSTCTL_MIGRATE_AUTO should be ignored, leaving auto-migrate on")
	}
}
