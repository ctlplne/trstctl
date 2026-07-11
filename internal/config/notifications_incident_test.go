// SPDX-License-Identifier: MPL-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

func TestIncidentNotificationConfigValidatesCredentialsNetworkAndTimeout(t *testing.T) {
	validPagerDuty := NotificationPagerDuty{
		Enabled: true, RoutingKeyFile: "/run/secrets/pagerduty",
		Endpoint: "https://events.pagerduty.com/v2/enqueue", Timeout: "7s",
	}
	validOpsGenie := NotificationOpsGenie{
		Enabled: true, APIKey: []byte("genie-key"),
		Endpoint: "https://api.opsgenie.com/v2/alerts", Timeout: "9s",
	}
	if errs := validateIncidentNotifications(validPagerDuty, validOpsGenie); len(errs) != 0 {
		t.Fatalf("valid incident notification config: %v", errs)
	}
	if got, err := validPagerDuty.TimeoutDuration(); err != nil || got != 7*time.Second {
		t.Fatalf("PagerDuty timeout = (%v, %v), want (7s, nil)", got, err)
	}

	badPagerDuty := NotificationPagerDuty{
		Enabled: true, RoutingKey: []byte("inline"), RoutingKeyFile: "/also/file",
		Endpoint: "http://10.0.0.9/v2/enqueue", AllowInsecureHTTP: true,
		Timeout: "forever", AllowPrivateCIDRs: []string{"not-a-cidr"},
	}
	badOpsGenie := NotificationOpsGenie{Enabled: true}
	joined := errorsText(validateIncidentNotifications(badPagerDuty, badOpsGenie))
	for _, want := range []string{
		"mutually exclusive", "timeout", "allow_private_cidrs", "loopback", "requires its credential",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("validation errors %q do not contain %q", joined, want)
		}
	}
}

func TestIncidentNotificationEnvOverlayKeepsSecretsByteNative(t *testing.T) {
	env := map[string]string{
		"TRSTCTL_NOTIFICATIONS_PAGERDUTY_ENABLED":             "true",
		"TRSTCTL_NOTIFICATIONS_PAGERDUTY_ROUTING_KEY":         "pd-key",
		"TRSTCTL_NOTIFICATIONS_PAGERDUTY_ALLOW_PRIVATE_CIDRS": "10.0.0.0/8, 192.168.0.0/16",
		"TRSTCTL_NOTIFICATIONS_OPSGENIE_ENABLED":              "true",
		"TRSTCTL_NOTIFICATIONS_OPSGENIE_API_KEY_FILE":         "/run/secrets/opsgenie",
		"TRSTCTL_NOTIFICATIONS_OPSGENIE_ALLOW_INSECURE_HTTP":  "true",
		"TRSTCTL_NOTIFICATIONS_OPSGENIE_ENDPOINT":             "http://127.0.0.1:8080/v2/alerts",
		"TRSTCTL_NOTIFICATIONS_OPSGENIE_TIMEOUT":              "3s",
	}
	pagerDuty := NotificationPagerDuty{}
	opsGenie := NotificationOpsGenie{}
	setIncidentNotificationEnv(func(key string) string { return env[key] }, &pagerDuty, &opsGenie)
	if !pagerDuty.Enabled || string(pagerDuty.RoutingKey) != "pd-key" || len(pagerDuty.AllowPrivateCIDRs) != 2 {
		t.Fatalf("PagerDuty env overlay = %+v", pagerDuty)
	}
	if !opsGenie.Enabled || opsGenie.APIKeyFile != "/run/secrets/opsgenie" || !opsGenie.AllowInsecureHTTP || opsGenie.Timeout != "3s" {
		t.Fatalf("OpsGenie env overlay = %+v", opsGenie)
	}
}

func errorsText(errs []error) string {
	parts := make([]string, 0, len(errs))
	for _, err := range errs {
		parts = append(parts, err.Error())
	}
	return strings.Join(parts, "; ")
}
