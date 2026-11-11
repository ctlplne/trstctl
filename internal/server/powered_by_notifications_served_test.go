// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/quotedprintable"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/branding"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/notify"
	notifyemail "trstctl.com/trstctl/internal/notify/email"
	"trstctl.com/trstctl/internal/notify/slack"
	"trstctl.com/trstctl/internal/notify/teams"
	"trstctl.com/trstctl/internal/notify/webhook"
)

// msp1Bodies keeps every body each channel received, by channel.
type msp1Bodies struct {
	mu     sync.Mutex
	bodies map[string][]string
}

func (b *msp1Bodies) add(channel string, body []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.bodies[channel] = append(b.bodies[channel], string(body))
}

func (b *msp1Bodies) all(channel string) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.bodies[channel]...)
}

type msp1Mail struct{ into *msp1Bodies }

func (m msp1Mail) Send(_ context.Context, _ string, _ []string, msg []byte) error {
	_, body, ok := bytes.Cut(msg, []byte("\r\n\r\n"))
	if !ok {
		return io.ErrUnexpectedEOF
	}
	decoded, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(body)))
	if err != nil {
		return err
	}
	m.into.add("email", decoded)
	return nil
}

// MSP-1, served: an expiry alert for a white-labeled tenant goes through the
// lifecycle scheduler, the outbox and the dispatcher, and every channel says
// "Powered by trstctl": Slack and Teams as a line under the alert, email as the
// body's first line, and the webhook's JSON as powered_by. The tenant's brand
// changes only colors, hostile ones, and still counts as white-label.
func TestServedWhiteLabeledTenantNotificationsSayPoweredByTrstctlMSP1(t *testing.T) {
	got := &msp1Bodies{bodies: map[string][]string{}}
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got.add(strings.TrimPrefix(r.URL.Path, "/"), body)
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(sink.Close)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LifecycleAlertBefore = 7 * 24 * time.Hour
		d.NotificationChannels = []notify.Notifier{
			notifyemail.New("smtp.example:587", "alerts@example.test", []string{"oncall@example.test"}, notifyemail.WithSender(msp1Mail{into: got})),
			slack.New(sink.URL+"/slack", slack.WithHTTPClient(sink.Client())),
			teams.New(sink.URL+"/teams", teams.WithHTTPClient(sink.Client())),
			webhook.New(sink.URL+"/webhook", []byte("msp1-served-webhook"), webhook.WithHTTPClient(sink.Client())),
		}
	})
	branding.SetSource(tenantBrandSource{tenant: h.tenant, brand: branding.Brand{
		TokenOverrides: map[string]string{"--foreground": "0 0% 100%", "--background": "0 0% 100%", "--font-size-body": "0px"},
	}})
	t.Cleanup(func() { branding.SetSource(nil) })
	tok := seedScopedToken(t, h.store, h.tenant, "owners:read", "owners:write", "identities:read", "identities:write",
		"certs:read", "certs:issue", "notifications:read")
	seedNearExpiryNotificationCertificate(t, h, tok, "msp-1-notify.served.test")
	if _, err := h.srv.RunLifecycleOnce(t.Context()); err != nil {
		t.Fatalf("run lifecycle scheduler: %v", err)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain notification outbox: %v", err)
	}

	only := func(channel string) string {
		t.Helper()
		bodies := got.all(channel)
		if len(bodies) != 1 {
			t.Fatalf("%s deliveries = %d, want 1: %q", channel, len(bodies), bodies)
		}
		return bodies[0]
	}
	var slackMsg, teamsCard struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal([]byte(only("slack")), &slackMsg); err != nil || !strings.HasSuffix(slackMsg.Text, "\nPowered by trstctl") ||
		!strings.Contains(slackMsg.Text, "msp-1-notify.served.test") {
		t.Errorf("the Slack message = %q (%v), want the alert with Powered by trstctl as its last line", slackMsg.Text, err)
	}
	if err := json.Unmarshal([]byte(only("teams")), &teamsCard); err != nil || !strings.HasSuffix(teamsCard.Text, "\n\nPowered by trstctl") {
		t.Errorf("the Teams card = %q (%v), want Powered by trstctl as its last line", teamsCard.Text, err)
	}
	var hook map[string]any
	if err := json.Unmarshal([]byte(only("webhook")), &hook); err != nil || hook["powered_by"] != "Powered by trstctl" || hook["tenant_id"] != h.tenant {
		t.Errorf("the webhook payload = %v (%v), want powered_by Powered by trstctl", hook, err)
	}
	if mail := only("email"); !strings.HasPrefix(mail, "Powered by trstctl\r\n\r\n") && !strings.HasPrefix(mail, "Powered by trstctl\n\n") {
		t.Errorf("the email body = %q, want Powered by trstctl as its first line", mail)
	}
}
