// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// A99: the operator private-egress policy PagerDuty and OpsGenie already had
// (exact private CIDRs, loopback-only insecure HTTP) now covers the Slack,
// Teams, SMS and SIEM channels, validated at config load the same way.
func TestNotificationChannelsValidatePrivateEgressPolicyA99(t *testing.T) {
	bad := Notifications{
		Slack: NotificationWebhook{Enabled: true, WebhookURL: "http://10.0.0.9/hook", AllowInsecureHTTP: true, AllowPrivateCIDRs: []string{"not-a-cidr"}},
		Teams: NotificationWebhook{Enabled: true, WebhookURL: "https://teams.internal.example/hook", AllowPrivateCIDRs: []string{"10.1.2.3/8"}},
		SMS:   NotificationSMS{Enabled: true, Endpoint: "https://sms.internal.example/", To: []string{"+15550100"}, AllowPrivateCIDRs: []string{"10.40.0.0/16"}},
		SIEM:  NotificationSIEM{Enabled: true, Endpoint: "http://siem.internal.example/collector", AllowInsecureHTTP: true},
	}
	joined := errorsText(validateNotifications(bad))
	for _, want := range []string{
		"notifications.slack.allow_private_cidrs", "notifications.slack.webhook_url must use https",
		"notifications.teams.allow_private_cidrs", "host bits",
		"notifications.siem.endpoint must use https", "loopback",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("validation errors %q do not contain %q", joined, want)
		}
	}
	if strings.Contains(joined, "notifications.sms") {
		t.Errorf("a well-formed SMS private-egress policy was rejected: %q", joined)
	}

	good := Notifications{
		Slack: NotificationWebhook{Enabled: true, WebhookURL: "https://10.40.0.9/hook", AllowPrivateCIDRs: []string{"10.40.0.0/16"}},
		SIEM:  NotificationSIEM{Enabled: true, Endpoint: "http://127.0.0.1:9/collector", AllowInsecureHTTP: true},
	}
	if errs := validateNotifications(good); len(errs) != 0 {
		t.Fatalf("valid private-egress policies rejected: %v", errs)
	}

	env := map[string]string{
		"TRSTCTL_NOTIFICATIONS_SLACK_ALLOW_PRIVATE_CIDRS": "10.40.0.0/16, 10.41.0.0/16",
		"TRSTCTL_NOTIFICATIONS_TEAMS_ALLOW_INSECURE_HTTP": "true",
		"TRSTCTL_NOTIFICATIONS_SMS_ALLOW_PRIVATE_CIDRS":   "192.168.7.0/24",
		"TRSTCTL_NOTIFICATIONS_SIEM_ALLOW_PRIVATE_CIDRS":  "10.0.0.0/8",
		"TRSTCTL_NOTIFICATIONS_SIEM_ALLOW_INSECURE_HTTP":  "true",
	}
	var n Notifications
	setNotificationEnv(func(key string) string { return env[key] }, &n)
	if len(n.Slack.AllowPrivateCIDRs) != 2 || !n.Teams.AllowInsecureHTTP || len(n.SMS.AllowPrivateCIDRs) != 1 || len(n.SIEM.AllowPrivateCIDRs) != 1 || !n.SIEM.AllowInsecureHTTP {
		t.Fatalf("env overlay = slack %v teams %v sms %v siem %v/%v", n.Slack.AllowPrivateCIDRs, n.Teams.AllowInsecureHTTP, n.SMS.AllowPrivateCIDRs, n.SIEM.AllowPrivateCIDRs, n.SIEM.AllowInsecureHTTP)
	}
}
