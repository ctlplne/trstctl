// SPDX-License-Identifier: MPL-2.0

package config

import (
	"strings"
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

// TestLifecycleParseAndEnv: JSON overlays and TRSTCTL_LIFECYCLE_* env vars set
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
		"TRSTCTL_LIFECYCLE_RENEW_BEFORE": "120h",
		"TRSTCTL_LIFECYCLE_ALERT_BEFORE": "12h",
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

func TestNotificationChannelEnv(t *testing.T) {
	env := map[string]string{
		"TRSTCTL_NOTIFICATIONS_SLACK_ENABLED":     "true",
		"TRSTCTL_NOTIFICATIONS_SLACK_WEBHOOK_URL": "https://hooks.slack.example/services/T/B/S",
		"TRSTCTL_NOTIFICATIONS_TEAMS_ENABLED":     "true",
		"TRSTCTL_NOTIFICATIONS_TEAMS_WEBHOOK_URL": "https://teams.example/webhook",
		"TRSTCTL_NOTIFICATIONS_EMAIL_ENABLED":     "true",
		"TRSTCTL_NOTIFICATIONS_EMAIL_SMTP_ADDR":   "smtp.example:587",
		"TRSTCTL_NOTIFICATIONS_EMAIL_FROM":        "alerts@example.test",
		"TRSTCTL_NOTIFICATIONS_EMAIL_TO":          "oncall@example.test, secops@example.test",
		"TRSTCTL_NOTIFICATIONS_EMAIL_USERNAME":    "smtp-user",
		"TRSTCTL_NOTIFICATIONS_EMAIL_PASSWORD":    "smtp-pass",
		"TRSTCTL_NOTIFICATIONS_SMS_ENABLED":       "true",
		"TRSTCTL_NOTIFICATIONS_SMS_ENDPOINT":      "https://sms-gateway.example/alerts",
		"TRSTCTL_NOTIFICATIONS_SMS_FROM":          "trstctl",
		"TRSTCTL_NOTIFICATIONS_SMS_TO":            "+15550100,+15550101",
		"TRSTCTL_NOTIFICATIONS_SMS_TOKEN":         "sms-token",
		"TRSTCTL_NOTIFICATIONS_SIEM_ENABLED":      "true",
		"TRSTCTL_NOTIFICATIONS_SIEM_ENDPOINT":     "https://siem.example/collector",
		"TRSTCTL_NOTIFICATIONS_SIEM_TOKEN":        "siem-token",
		"TRSTCTL_NOTIFICATIONS_SIEM_SOURCE":       "trstctl-prod",
	}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load notification config: %v", err)
	}
	if !cfg.Notifications.Slack.Enabled || cfg.Notifications.Slack.WebhookURL == "" {
		t.Fatalf("slack notification env not loaded: %+v", cfg.Notifications.Slack)
	}
	if !cfg.Notifications.Teams.Enabled || cfg.Notifications.Teams.WebhookURL == "" {
		t.Fatalf("teams notification env not loaded: %+v", cfg.Notifications.Teams)
	}
	if !cfg.Notifications.Email.Enabled || len(cfg.Notifications.Email.To) != 2 || string(cfg.Notifications.Email.Password) != "smtp-pass" {
		t.Fatalf("email notification env not loaded: %+v", cfg.Notifications.Email)
	}
	if !cfg.Notifications.SMS.Enabled || len(cfg.Notifications.SMS.To) != 2 || string(cfg.Notifications.SMS.Token) != "sms-token" {
		t.Fatalf("sms notification env not loaded: %+v", cfg.Notifications.SMS)
	}
	if !cfg.Notifications.SIEM.Enabled || cfg.Notifications.SIEM.Source != "trstctl-prod" || string(cfg.Notifications.SIEM.Token) != "siem-token" {
		t.Fatalf("siem notification env not loaded: %+v", cfg.Notifications.SIEM)
	}
}

func TestNotificationChannelValidation(t *testing.T) {
	cfg := Default()
	cfg.Notifications.SMS.Enabled = true
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "notifications.sms.endpoint") || !strings.Contains(err.Error(), "notifications.sms.to") {
		t.Fatalf("Validate() = %v, want missing SMS endpoint and recipients", err)
	}
}
