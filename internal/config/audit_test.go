package config_test

import (
	"testing"

	"certctl.io/certctl/internal/config"
)

// TestAuditDefaults: the audit export key has a default on-disk location (so it
// persists across restarts) and retention is unbounded by default (the event log
// is the immutable source of truth).
func TestAuditDefaults(t *testing.T) {
	c := config.Default()
	if c.Audit.SigningKeyFile == "" {
		t.Error("audit.signing_key_file must default to a path so the export key persists")
	}
	if c.Audit.Retention != "" {
		t.Errorf("audit.retention default = %q, want empty (indefinite)", c.Audit.Retention)
	}
}

// TestAuditEnvOverrides: the audit settings are configurable from the environment.
func TestAuditEnvOverrides(t *testing.T) {
	env := map[string]string{
		"CERTCTL_POSTGRES_MODE":          "external",
		"CERTCTL_POSTGRES_DSN":           "postgres://u:p@h:5432/db?sslmode=require",
		"CERTCTL_NATS_MODE":              "external",
		"CERTCTL_NATS_URL":               "nats://h:4222",
		"CERTCTL_AUDIT_SIGNING_KEY_FILE": "/var/lib/certctl/audit.pem",
		"CERTCTL_AUDIT_RETENTION":        "8760h",
		"CERTCTL_AUDIT_ARCHIVE_DIR":      "/var/lib/certctl/audit-archive",
	}
	cfg, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Audit.SigningKeyFile != "/var/lib/certctl/audit.pem" {
		t.Errorf("signing_key_file = %q", cfg.Audit.SigningKeyFile)
	}
	if cfg.Audit.Retention != "8760h" {
		t.Errorf("retention = %q", cfg.Audit.Retention)
	}
	if cfg.Audit.ArchiveDir != "/var/lib/certctl/audit-archive" {
		t.Errorf("archive_dir = %q", cfg.Audit.ArchiveDir)
	}
}

// TestAuditRetentionValidated: a malformed retention duration fails fast.
func TestAuditRetentionValidated(t *testing.T) {
	env := map[string]string{
		"CERTCTL_POSTGRES_MODE":   "external",
		"CERTCTL_POSTGRES_DSN":    "postgres://u:p@h:5432/db?sslmode=require",
		"CERTCTL_NATS_MODE":       "external",
		"CERTCTL_NATS_URL":        "nats://h:4222",
		"CERTCTL_AUDIT_RETENTION": "not-a-duration",
	}
	if _, err := config.Load(func(k string) string { return env[k] }); err == nil {
		t.Fatal("Load accepted a malformed audit.retention")
	}
}
