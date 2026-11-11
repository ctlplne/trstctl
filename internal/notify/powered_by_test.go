// SPDX-License-Identifier: BUSL-1.1

package notify_test

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

	"trstctl.com/trstctl/internal/branding"
	"trstctl.com/trstctl/internal/notify"
	notifyemail "trstctl.com/trstctl/internal/notify/email"
	"trstctl.com/trstctl/internal/notify/slack"
	"trstctl.com/trstctl/internal/notify/teams"
	"trstctl.com/trstctl/internal/notify/webhook"
)

// oneWhiteLabelTenant brands one tenant, as the Provider edition's resolver
// does, and serves the built-in brand to every other tenant.
type oneWhiteLabelTenant struct{ tenant string }

func (s oneWhiteLabelTenant) Resolve(_ context.Context, _, tenantID string) branding.Brand {
	if tenantID == s.tenant {
		return branding.Brand{ProductName: "Northwind Managed PKI", TokenOverrides: map[string]string{"--foreground": "0 0% 100%"}}
	}
	return branding.Default()
}

func (oneWhiteLabelTenant) TenantForHost(context.Context, string) string { return "" }

type capturedBodies struct {
	mu     sync.Mutex
	bodies map[string][]string
}

func (c *capturedBodies) add(channel string, body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bodies[channel] = append(c.bodies[channel], string(body))
}

func (c *capturedBodies) last(channel string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	got := c.bodies[channel]
	if len(got) == 0 {
		return ""
	}
	return got[len(got)-1]
}

type capturedMail struct{ into *capturedBodies }

func (m capturedMail) Send(_ context.Context, _ string, _ []string, msg []byte) error {
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

// MSP-1: a white-labeled tenant's notifications carry a visible "Powered by
// trstctl" line: Slack and Teams as a line under the message, email as the
// body's first line, and a webhook's JSON as powered_by. The line comes from
// the tenant's brand on every delivery, so a payload cannot forge it, change
// its words or remove it, and a tenant on the built-in brand gets none, even
// when its payload claims one.
func TestWhiteLabeledTenantNotificationsSayPoweredByTrstctlMSP1(t *testing.T) {
	branding.SetSource(oneWhiteLabelTenant{tenant: "t-msp"})
	t.Cleanup(func() { branding.SetSource(nil) })
	got := &capturedBodies{bodies: map[string][]string{}}
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got.add(strings.TrimPrefix(r.URL.Path, "/"), body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(sink.Close)
	d := notify.NewDispatcher(
		slack.New(sink.URL+"/slack", slack.WithHTTPClient(sink.Client())),
		teams.New(sink.URL+"/teams", teams.WithHTTPClient(sink.Client())),
		webhook.New(sink.URL+"/webhook", []byte("msp1-webhook-signing"), webhook.WithHTTPClient(sink.Client())),
		notifyemail.New("smtp.example.test:587", "alerts@example.test", []string{"oncall@example.test"}, notifyemail.WithSender(capturedMail{into: got})),
	)
	send := func(tenant, forged string) {
		t.Helper()
		payload, err := json.Marshal(map[string]any{"kind": notify.KindCertificateExpiry, "tenant_id": tenant,
			"subject": "CN=api." + tenant + ".example.test", "powered_by": forged})
		if err != nil {
			t.Fatal(err)
		}
		if err := d.Dispatch(context.Background(), payload); err != nil {
			t.Fatalf("dispatch for %s: %v", tenant, err)
		}
	}

	send("t-msp", "Powered by Northwind")
	if text := slackText(t, got.last("slack")); !strings.HasSuffix(text, "\nPowered by trstctl") {
		t.Errorf("the Slack message = %q, want its last line to be Powered by trstctl", text)
	}
	if text := teamsText(t, got.last("teams")); !strings.HasSuffix(text, "\n\nPowered by trstctl") {
		t.Errorf("the Teams card = %q, want its last line to be Powered by trstctl", text)
	}
	var hook map[string]any
	if err := json.Unmarshal([]byte(got.last("webhook")), &hook); err != nil || hook["powered_by"] != "Powered by trstctl" {
		t.Errorf("the webhook payload's powered_by = %v (%v), want Powered by trstctl", hook["powered_by"], err)
	}
	if mail := got.last("email"); !strings.HasPrefix(mail, "Powered by trstctl\r\n\r\n") && !strings.HasPrefix(mail, "Powered by trstctl\n\n") {
		t.Errorf("the email body = %q, want its first line to be Powered by trstctl", mail)
	}
	for channel, bodies := range got.bodies {
		for _, body := range bodies {
			if strings.Contains(body, "Northwind") {
				t.Errorf("%s carried the forged line: %s", channel, body)
			}
		}
	}

	send("t-plain", "Powered by trstctl")
	for _, channel := range []string{"slack", "teams", "webhook", "email"} {
		if body := got.last(channel); body == "" || strings.Contains(body, "Powered by") || strings.Contains(body, "powered_by") {
			t.Errorf("a tenant on the built-in brand got a line on %s: %q", channel, body)
		}
	}
}

func slackText(t *testing.T, body string) string {
	t.Helper()
	var msg struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal([]byte(body), &msg); err != nil {
		t.Fatalf("slack body %q: %v", body, err)
	}
	return msg.Text
}

func teamsText(t *testing.T, body string) string {
	t.Helper()
	var card struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal([]byte(body), &card); err != nil {
		t.Fatalf("teams body %q: %v", body, err)
	}
	return card.Text
}
