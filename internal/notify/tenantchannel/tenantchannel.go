// SPDX-License-Identifier: BUSL-1.1

// Package tenantchannel turns a tenant-authored notification channel row into
// the notifier of its family (A98). A tenant authors a channel through
// /api/v1/notification-channels with an endpoint and a credential reference
// into its own secret store; the dispatcher used to POST the raw alert JSON to
// every such endpoint whatever its family, so a tenant Slack or PagerDuty
// channel could never deliver. Build gives each row the same transport the
// operator-configured family uses, with the referenced tenant secret as its
// credential. The credential is held only for one delivery and released with
// the channel (AN-8).
package tenantchannel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/notify/opsgenie"
	"trstctl.com/trstctl/internal/notify/pagerduty"
	"trstctl.com/trstctl/internal/notify/siem"
	"trstctl.com/trstctl/internal/notify/slack"
	"trstctl.com/trstctl/internal/notify/teams"
	"trstctl.com/trstctl/internal/notify/webhook"
	"trstctl.com/trstctl/internal/store"
)

// Channel is a tenant-authored notifier. Release wipes the credential it was
// built with and must run once delivery of the alert is over.
type Channel interface {
	notify.Notifier
	Release()
}

// TenantFamilies are the channel families a tenant may author. Each delivers
// in that family's own wire shape.
var TenantFamilies = []string{"slack", "msteams", "webhook", "pagerduty", "opsgenie", "siem"}

// Family canonicalises a channel family name the way the API does.
func Family(name string) string {
	id := strings.ToLower(strings.TrimSpace(name))
	switch strings.NewReplacer(" ", "", "-", "", "_", "").Replace(id) {
	case "teams", "microsoftteams", "msftteams", "msteams":
		return "msteams"
	default:
		return id
	}
}

// TenantAuthored reports whether a tenant may author a channel of family.
func TenantAuthored(family string) bool {
	family = Family(family)
	for _, f := range TenantFamilies {
		if f == family {
			return true
		}
	}
	return false
}

// OperatorOnly reports whether family is delivered only through the server's
// notifications configuration: SMTP email and the SMS gateway need sender,
// recipient and transport settings a tenant channel row cannot carry.
func OperatorOnly(family string) bool {
	switch Family(family) {
	case "email", "sms":
		return true
	}
	return false
}

// OperatorOnlyReason is the refusal a tenant gets for an operator-only family.
func OperatorOnlyReason(family string) string {
	return Family(family) + " is an operator-configured family: it is wired in the server's notifications configuration, not as a tenant channel; tenant channels support " + strings.Join(TenantFamilies, ", ")
}

// Describe says how a tenant-authored channel of family delivers.
func Describe(family string) string {
	switch Family(family) {
	case "slack":
		return "tenant-authored Slack incoming-webhook text delivery"
	case "msteams":
		return "tenant-authored Microsoft Teams MessageCard delivery"
	case "webhook":
		return "tenant-authored webhook delivery of the alert JSON, HMAC-signed under the referenced credential"
	case "pagerduty":
		return "tenant-authored PagerDuty Events API v2 trigger with the referenced routing key"
	case "opsgenie":
		return "tenant-authored OpsGenie Alert API create with the referenced API key"
	case "siem":
		return "tenant-authored SIEM collector event, bearer-authenticated when a credential is referenced"
	case "email", "sms":
		return "operator-configured family; not deliverable as a tenant channel"
	}
	return "tenant-authored notification.* outbox fanout"
}

type channel struct {
	notify.Notifier
	release []func()
}

func (c *channel) Release() {
	for _, f := range c.release {
		f()
	}
	c.release = nil
}

// Build returns the notifier for row. credential is the resolved value of the
// row's credential reference, or nil when none is set; Build takes ownership
// of it and destroys it on Release or on any error. client is an injected
// transport (tests); nil keeps each family's SSRF-safe default and its
// public-HTTPS endpoint check.
func Build(row store.NotificationChannel, credential *secret.Buffer, client notify.HTTPDoer) (Channel, error) {
	fail := func(err error) (Channel, error) {
		if credential != nil {
			credential.Destroy()
		}
		return nil, err
	}
	family := Family(row.ChannelType)
	if family == "" {
		family = Family(row.ID)
	}
	endpoint := strings.TrimSpace(row.EndpointURL)
	if endpoint == "" {
		return fail(fmt.Errorf("%s: tenant channel has no endpoint", family))
	}
	needCredential := func() ([]byte, error) {
		if credential == nil || credential.Len() == 0 {
			return nil, fmt.Errorf("%s: a credential reference is required and none resolved", family)
		}
		return credential.Bytes(), nil
	}
	out := &channel{}
	if credential != nil {
		out.release = append(out.release, credential.Destroy)
	}
	switch family {
	case "slack":
		var opts []slack.Option
		if client != nil {
			opts = append(opts, slack.WithHTTPClient(client))
		}
		out.Notifier = slack.New(endpoint, opts...)
	case "msteams":
		var opts []teams.Option
		if client != nil {
			opts = append(opts, teams.WithHTTPClient(client))
		}
		out.Notifier = teams.New(endpoint, opts...)
	case "webhook":
		if strings.TrimSpace(row.CredentialRef) == "" {
			out.Notifier = plainWebhook{id: family, endpoint: endpoint, client: client}
			break
		}
		key, err := needCredential()
		if err != nil {
			return fail(err)
		}
		var opts []webhook.Option
		if client != nil {
			opts = append(opts, webhook.WithHTTPClient(client))
		}
		// The webhook channel keeps the key by reference; the locked buffer
		// outlives it until Release.
		out.Notifier = webhook.New(endpoint, key, opts...)
	case "pagerduty":
		key, err := needCredential()
		if err != nil {
			return fail(err)
		}
		opts := []pagerduty.Option{pagerduty.WithEndpoint(endpoint)}
		if client != nil {
			opts = append(opts, pagerduty.WithHTTPClient(client))
		}
		ch, err := pagerduty.New(key, opts...)
		if err != nil {
			return fail(err)
		}
		out.Notifier = ch
		out.release = append(out.release, ch.Close)
	case "opsgenie":
		key, err := needCredential()
		if err != nil {
			return fail(err)
		}
		opts := []opsgenie.Option{opsgenie.WithEndpoint(endpoint)}
		if client != nil {
			opts = append(opts, opsgenie.WithHTTPClient(client))
		}
		ch, err := opsgenie.New(key, opts...)
		if err != nil {
			return fail(err)
		}
		out.Notifier = ch
		out.release = append(out.release, ch.Close)
	case "siem":
		var token []byte
		if strings.TrimSpace(row.CredentialRef) != "" {
			var err error
			if token, err = needCredential(); err != nil {
				return fail(err)
			}
		}
		var opts []siem.Option
		if client != nil {
			opts = append(opts, siem.WithHTTPClient(client))
		}
		out.Notifier = siem.New(endpoint, token, opts...)
	case "email", "sms":
		return fail(errors.New(OperatorOnlyReason(family)))
	default:
		return fail(fmt.Errorf("unsupported tenant channel family %q", family))
	}
	return out, nil
}

// plainWebhook is a tenant webhook without a credential reference: the alert
// JSON POSTed unsigned, as tenant webhooks always delivered. A referenced
// credential upgrades the row to the HMAC-signed webhook family.
type plainWebhook struct {
	id       string
	endpoint string
	client   notify.HTTPDoer
}

func (c plainWebhook) Name() string { return c.id }

func (c plainWebhook) Notify(ctx context.Context, alert notify.Alert) error {
	client := c.client
	if client == nil {
		if err := netsec.ValidatePublicHTTPSURL(c.endpoint); err != nil {
			return fmt.Errorf("tenant channel %q: validate endpoint: %w", c.id, err)
		}
		client = netsec.SafeClient(10 * time.Second)
	}
	payload, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("tenant channel %q: marshal alert: %w", c.id, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("tenant channel %q: invalid endpoint", c.id)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Trstctl-Notification-Channel", c.id)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("tenant channel %q: request failed", c.id)
	}
	defer func() { _ = resp.Body.Close() }()
	_ = secret.DrainBounded(resp.Body, 1024)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("tenant channel %q: endpoint returned HTTP %d", c.id, resp.StatusCode)
	}
	return nil
}
