// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
	"time"
)

// A236-L4: secrets.deleted_retention keeps a deleted secret 30 days by
// default, 0s keeps none, the environment overrides it, and a negative or
// over-a-year value is refused at load.
func TestSecretsDeletedRetentionA236L4(t *testing.T) {
	if d, err := (Secrets{}).DeletedRetentionDuration(); err != nil || d != 30*24*time.Hour {
		t.Fatalf("default = %v err=%v, want 720h", d, err)
	}
	for value, want := range map[string]time.Duration{"0s": 0, "168h": 7 * 24 * time.Hour, "8760h": 365 * 24 * time.Hour} {
		if d, err := (Secrets{DeletedRetention: value}).DeletedRetentionDuration(); err != nil || d != want {
			t.Fatalf("%s = %v err=%v, want %v", value, d, err, want)
		}
	}
	env := func(value string) func(string) string {
		return func(key string) string {
			if key == "TRSTCTL_SECRETS_DELETED_RETENTION" {
				return value
			}
			return ""
		}
	}
	cfg, err := Load(env("72h"))
	if err != nil {
		t.Fatal(err)
	}
	if d, err := cfg.Secrets.DeletedRetentionDuration(); err != nil || d != 72*time.Hour {
		t.Fatalf("environment override = %v err=%v, want 72h", d, err)
	}
	for _, bad := range []string{"-1h", "8761h", "a month"} {
		if _, err := Load(env(bad)); err == nil || !strings.Contains(err.Error(), "secrets.deleted_retention") {
			t.Fatalf("%q loaded (err=%v); want a refusal naming secrets.deleted_retention", bad, err)
		}
	}
}
