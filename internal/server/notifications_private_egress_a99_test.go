// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/notify"
)

// A99: operator-configured Slack, Teams, SMS and SIEM channels can be pointed
// at an internal receiver through the same bounded private-egress policy the
// incident channels have — exact private CIDRs, loopback-only insecure HTTP —
// while keeping the SSRF guard everywhere else. The policy is checked when
// the channels are built, so a bad entry fails startup, not the first alert.
func TestOperatorChannelsHonourThePrivateEgressPolicyA99(t *testing.T) {
	var mu sync.Mutex
	var bodies [][]byte
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()
	alert := notify.Alert{Kind: notify.KindCertificateExpiry, TenantID: "t1", Subject: "svc.example", Severity: "critical", Detail: "expires in 7 days"}
	ctx := context.Background()

	// A loopback receiver inside the granted range, over the explicitly
	// allowed insecure HTTP a development emulator needs.
	channels, err := notificationChannelsFromConfig(config.Notifications{
		Slack: config.NotificationWebhook{Enabled: true, WebhookURL: sink.URL + "/hook", AllowPrivateCIDRs: []string{"127.0.0.0/8"}, AllowInsecureHTTP: true},
	}, nil)
	if err != nil || len(channels) != 1 {
		t.Fatalf("slack with private-egress policy: %v (%d channels)", err, len(channels))
	}
	if err := channels[0].Notify(ctx, alert); err != nil {
		t.Fatalf("slack delivery to the allowed internal receiver: %v", err)
	}
	mu.Lock()
	delivered := len(bodies)
	var payload map[string]any
	if delivered == 1 {
		_ = json.Unmarshal(bodies[0], &payload)
	}
	mu.Unlock()
	if delivered != 1 || payload["text"] == nil {
		t.Fatalf("internal receiver got %d deliveries, payload %v; want one Slack text message", delivered, payload)
	}

	// The same receiver without a policy stays behind the SSRF guard.
	bare, err := notificationChannelsFromConfig(config.Notifications{
		Slack: config.NotificationWebhook{Enabled: true, WebhookURL: sink.URL + "/hook"},
	}, nil)
	if err != nil || len(bare) != 1 {
		t.Fatalf("bare slack: %v", err)
	}
	if err := bare[0].Notify(ctx, alert); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("bare slack to a loopback http receiver = %v, want the SSRF guard's https refusal", err)
	}

	// An unusable allowlist entry is a startup error.
	if _, err := notificationChannelsFromConfig(config.Notifications{
		Teams: config.NotificationWebhook{Enabled: true, WebhookURL: "https://teams.internal.example/hook", AllowPrivateCIDRs: []string{"not-a-cidr"}},
	}, nil); err == nil || !strings.Contains(err.Error(), "allow_private_cidrs") {
		t.Fatalf("teams with a bad allowlist entry = %v, want a config error naming allow_private_cidrs", err)
	}

	// A private HTTPS collector inside the granted range builds; the dial-time
	// guard enforces the range. One outside the range is refused at startup.
	if _, err := notificationChannelsFromConfig(config.Notifications{
		SIEM: config.NotificationSIEM{Enabled: true, Endpoint: "https://10.40.0.9/collector", Token: []byte("t"), AllowPrivateCIDRs: []string{"10.40.0.0/16"}},
	}, nil); err != nil {
		t.Fatalf("siem inside its allowed range: %v", err)
	}
	if _, err := notificationChannelsFromConfig(config.Notifications{
		SMS: config.NotificationSMS{Enabled: true, Endpoint: "https://10.50.0.9/sms", To: []string{"+15550100"}, Token: []byte("t"), AllowPrivateCIDRs: []string{"10.40.0.0/16"}},
	}, nil); err == nil || !strings.Contains(err.Error(), "not public") {
		t.Fatalf("sms outside its allowed range = %v, want the SSRF refusal at startup", err)
	}
}
