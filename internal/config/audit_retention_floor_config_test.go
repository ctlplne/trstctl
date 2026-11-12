// SPDX-License-Identifier: BUSL-1.1

package config_test

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// OD-11 (A233-L5): the operator's audit retention floor defaults to a year,
// loads from the environment, turns off with 0s, and a malformed, negative or
// over-ten-year floor fails startup.
func TestEventProtectionAuditRetentionFloorConfigOD11(t *testing.T) {
	cfg := config.Default()
	if got, err := cfg.Privacy.EventProtection.AuditRetentionFloorDuration(); err != nil || got != 8760*time.Hour {
		t.Fatalf("default floor = %s, %v", got, err)
	}
	env := map[string]string{"TRSTCTL_PRIVACY_EVENT_PROTECTION_AUDIT_RETENTION_FLOOR": "2160h"}
	loaded, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, err := loaded.Privacy.EventProtection.AuditRetentionFloorDuration(); err != nil || got != 2160*time.Hour {
		t.Fatalf("env floor = %s, %v", got, err)
	}
	off := config.Default()
	off.Privacy.EventProtection.AuditRetentionFloor = "0s"
	if got, err := off.Privacy.EventProtection.AuditRetentionFloorDuration(); err != nil || got != 0 {
		t.Fatalf("0s floor = %s, %v", got, err)
	}
	if err := off.Validate(); err != nil {
		t.Fatalf("Validate refused the floor turned off: %v", err)
	}
	for _, bad := range []string{"a year", "-1h", "87601h", "1y"} {
		cfg := config.Default()
		cfg.Privacy.EventProtection.AuditRetentionFloor = bad
		if err := cfg.Validate(); err == nil {
			t.Errorf("Validate accepted audit_retention_floor %q", bad)
		}
	}
}
