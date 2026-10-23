// SPDX-License-Identifier: BUSL-1.1

package tenantchannel_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/notify/tenantchannel"
	"trstctl.com/trstctl/internal/store"
)

type captureDoer struct {
	req  *http.Request
	body []byte
}

func (c *captureDoer) Do(req *http.Request) (*http.Response, error) {
	c.req = req
	if req.Body != nil {
		c.body, _ = io.ReadAll(req.Body)
	}
	// OpsGenie answers a create with a JSON acceptance; the other families
	// ignore the body.
	return &http.Response{StatusCode: http.StatusAccepted, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"result":"Request will be processed","requestId":"a98-request"}`))}, nil
}

// A98: tenant channel rows become the family's own notifier.
func TestBuildDeliversEachFamilyInItsOwnShapeA98(t *testing.T) {
	ctx := context.Background()
	alert := notify.Alert{Kind: notify.KindCertificateExpiry, TenantID: "t1", Subject: "svc.example", Severity: "critical", Detail: "expires in 7 days"}

	doer := &captureDoer{}
	teams, err := tenantchannel.Build(store.NotificationChannel{ID: "msteams", ChannelType: "msteams", EndpointURL: "https://teams.example.test/hook", Enabled: true}, nil, doer)
	if err != nil {
		t.Fatalf("build msteams: %v", err)
	}
	if teams.Name() != "msteams" {
		t.Fatalf("msteams name = %q", teams.Name())
	}
	if err := teams.Notify(ctx, alert); err != nil {
		t.Fatalf("teams notify: %v", err)
	}
	var card map[string]any
	if err := json.Unmarshal(doer.body, &card); err != nil || card["@type"] != "MessageCard" {
		t.Fatalf("teams body = %s (%v), want a MessageCard", doer.body, err)
	}
	teams.Release()

	// PagerDuty and OpsGenie need the referenced credential; without one the
	// channel is refused at build time, never silently unauthenticated.
	if _, err := tenantchannel.Build(store.NotificationChannel{ID: "pagerduty", ChannelType: "pagerduty", EndpointURL: "https://events.pagerduty.com/v2/enqueue", Enabled: true}, nil, doer); err == nil || !strings.Contains(err.Error(), "credential") {
		t.Fatalf("pagerduty without credential = %v, want a credential error", err)
	}
	key, err := secret.NewFrom([]byte("genie-key-0123456789"))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	genie, err := tenantchannel.Build(store.NotificationChannel{ID: "opsgenie", ChannelType: "opsgenie", EndpointURL: "https://api.opsgenie.test/v2/alerts", Enabled: true, CredentialRef: "secret://x"}, key, doer)
	if err != nil {
		t.Fatalf("build opsgenie: %v", err)
	}
	if err := genie.Notify(ctx, alert); err != nil {
		t.Fatalf("opsgenie notify: %v", err)
	}
	if got := doer.req.Header.Get("Authorization"); got != "GenieKey genie-key-0123456789" {
		t.Fatalf("opsgenie authorization = %q", got)
	}
	genie.Release()

	// Families whose delivery the tenant record cannot describe are refused.
	for _, family := range []string{"email", "sms"} {
		if _, err := tenantchannel.Build(store.NotificationChannel{ID: family, ChannelType: family, EndpointURL: "https://x.example.test", Enabled: true}, nil, doer); err == nil || !strings.Contains(err.Error(), "operator-configured") {
			t.Fatalf("%s tenant channel = %v, want refusal naming operator-configured families", family, err)
		}
	}
}
