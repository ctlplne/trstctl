// SPDX-License-Identifier: MPL-2.0

package config_test

import (
	"testing"

	"trstctl.com/trstctl/internal/config"
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
	if !c.Privacy.Retention.Enabled {
		t.Error("privacy.retention.enabled must default on so non-audit PII has enforced retention")
	}
	if c.Privacy.Retention.Interval == "" || c.Privacy.Retention.Certificates == "" || c.Privacy.Retention.Access == "" {
		t.Errorf("privacy retention defaults incomplete: %+v", c.Privacy.Retention)
	}
}

// TestAuditEnvOverrides: the audit settings are configurable from the environment.
func TestAuditEnvOverrides(t *testing.T) {
	env := map[string]string{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		"TRSTCTL_POSTGRES_MODE":                       "external",
		"TRSTCTL_POSTGRES_DSN":                        "postgres://u:p@h:5432/db?sslmode=require",
		"TRSTCTL_NATS_MODE":                           "external",
		"TRSTCTL_NATS_URL":                            "nats://h:4222",
		"TRSTCTL_SIGNER_AUTH_TOKEN_COMMAND":           "/usr/local/bin/trstctl-sign-approve",
		"TRSTCTL_SIGNER_ALLOW_CO_RESIDENT_AUTHORIZER": "false",
		"TRSTCTL_AUDIT_SIGNING_KEY_FILE":              "/var/lib/trstctl/audit.pem",
		"TRSTCTL_AUDIT_RETENTION":                     "8760h",
		"TRSTCTL_AUDIT_ARCHIVE_DIR":                   "/var/lib/trstctl/audit-archive",
		"TRSTCTL_PRIVACY_RETENTION_ENABLED":           "true",
		"TRSTCTL_PRIVACY_RETENTION_INTERVAL":          "12h",
		"TRSTCTL_PRIVACY_RETENTION_OWNERS":            "8760h",
		"TRSTCTL_PRIVACY_RETENTION_ACCESS":            "720h",
	}
	cfg, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Audit.SigningKeyFile != "/var/lib/trstctl/audit.pem" {
		t.Errorf("signing_key_file = %q", cfg.Audit.SigningKeyFile)
	}
	if cfg.Audit.Retention != "8760h" {
		t.Errorf("retention = %q", cfg.Audit.Retention)
	}
	if cfg.Audit.ArchiveDir != "/var/lib/trstctl/audit-archive" {
		t.Errorf("archive_dir = %q", cfg.Audit.ArchiveDir)
	}
	if cfg.Privacy.Retention.Interval != "12h" || cfg.Privacy.Retention.Owners != "8760h" || cfg.Privacy.Retention.Access != "720h" {
		t.Errorf("privacy retention env overrides = %+v", cfg.Privacy.Retention)
	}
}

// TestAuditRetentionValidated: a malformed retention duration fails fast.
func TestAuditRetentionValidated(t *testing.T) {
	env := map[string]string{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		"TRSTCTL_POSTGRES_MODE":   "external",
		"TRSTCTL_POSTGRES_DSN":    "postgres://u:p@h:5432/db?sslmode=require",
		"TRSTCTL_NATS_MODE":       "external",
		"TRSTCTL_NATS_URL":        "nats://h:4222",
		"TRSTCTL_AUDIT_RETENTION": "not-a-duration",
	}
	if _, err := config.Load(func(k string) string { return env[k] }); err == nil {
		t.Fatal("Load accepted a malformed audit.retention")
	}
}

func TestPrivacyRetentionValidated(t *testing.T) {
	env := map[string]string{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		"TRSTCTL_POSTGRES_MODE":              "external",
		"TRSTCTL_POSTGRES_DSN":               "postgres://u:p@h:5432/db?sslmode=require",
		"TRSTCTL_NATS_MODE":                  "external",
		"TRSTCTL_NATS_URL":                   "nats://h:4222",
		"TRSTCTL_PRIVACY_RETENTION_INTERVAL": "not-a-duration",
	}
	if _, err := config.Load(func(k string) string { return env[k] }); err == nil {
		t.Fatal("Load accepted a malformed privacy.retention.interval")
	}
	env["TRSTCTL_PRIVACY_RETENTION_INTERVAL"] = "24h"
	env["TRSTCTL_PRIVACY_RETENTION_OWNERS"] = "0s"
	if _, err := config.Load(func(k string) string { return env[k] }); err == nil {
		t.Fatal("Load accepted a non-positive privacy.retention.owners")
	}
}
