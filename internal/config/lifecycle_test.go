package config

import (
	"testing"
	"time"
)

// TestLifecycleDefaults: the built-in config carries sane renewal/alert
// thresholds and they parse to positive durations.
func TestLifecycleDefaults(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
	renew, err := cfg.Lifecycle.RenewBeforeDuration()
	if err != nil {
		t.Fatalf("RenewBeforeDuration: %v", err)
	}
	alert, err := cfg.Lifecycle.AlertBeforeDuration()
	if err != nil {
		t.Fatalf("AlertBeforeDuration: %v", err)
	}
	if renew <= 0 || alert <= 0 {
		t.Errorf("thresholds must be positive: renew=%s alert=%s", renew, alert)
	}
}

// TestLifecycleParseAndEnv: JSON overlays and CERTCTL_LIFECYCLE_* env vars set
// the thresholds.
func TestLifecycleParseAndEnv(t *testing.T) {
	cfg, err := Parse([]byte(`{"lifecycle":{"renew_before":"240h","alert_before":"48h"}}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, _ := cfg.Lifecycle.RenewBeforeDuration(); got != 240*time.Hour {
		t.Errorf("renew_before = %s, want 240h", got)
	}

	env := map[string]string{
		"CERTCTL_LIFECYCLE_RENEW_BEFORE": "120h",
		"CERTCTL_LIFECYCLE_ALERT_BEFORE": "12h",
	}
	loaded, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, _ := loaded.Lifecycle.RenewBeforeDuration(); got != 120*time.Hour {
		t.Errorf("env renew_before = %s, want 120h", got)
	}
	if got, _ := loaded.Lifecycle.AlertBeforeDuration(); got != 12*time.Hour {
		t.Errorf("env alert_before = %s, want 12h", got)
	}
}

// TestLifecycleRejectsBadDuration: an unparseable threshold fails validation.
func TestLifecycleRejectsBadDuration(t *testing.T) {
	cfg := Default()
	cfg.Lifecycle.RenewBefore = "not-a-duration"
	if err := cfg.Validate(); err == nil {
		t.Error("Validate accepted an invalid lifecycle.renew_before")
	}
}
