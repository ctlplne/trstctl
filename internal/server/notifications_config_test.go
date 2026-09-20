// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestNotificationChannelsFromConfigBuildsFiveCAPOBS05(t *testing.T) {
	channels, err := notificationChannelsFromConfig(config.Notifications{
		Slack: config.NotificationWebhook{Enabled: true, WebhookURL: "https://hooks.slack.example/services/T/B/S"},
		Teams: config.NotificationWebhook{Enabled: true, WebhookURL: "https://teams.example/webhook"},
		Email: config.NotificationEmail{
			Enabled: true, SMTPAddr: "smtp.example:587", From: "alerts@example.test",
			To: []string{"oncall@example.test"}, Username: "smtp-user", Password: []byte("smtp-pass"),
		},
		SMS: config.NotificationSMS{
			Enabled: true, Endpoint: "https://sms-gateway.example/alerts", From: "trstctl",
			To: []string{"+15550100"}, Token: []byte("sms-token"),
		},
		SIEM: config.NotificationSIEM{Enabled: true, Endpoint: "https://siem.example/collector", Token: []byte("siem-token")},
	})
	if err != nil {
		t.Fatalf("notificationChannelsFromConfig: %v", err)
	}
	got := map[string]bool{}
	for _, ch := range channels {
		got[ch.Name()] = true
	}
	for _, want := range []string{"email", "slack", "msteams", "sms", "siem"} {
		if !got[want] {
			t.Fatalf("configured channel names = %#v, missing %q", got, want)
		}
	}
}
