// SPDX-License-Identifier: MPL-2.0

// Package sms is the SMS notification channel. It posts a small JSON message to an
// operator-managed SMS gateway, authenticated with an optional bearer token. The
// gateway owns provider-specific details such as Twilio, SNS, or another carrier API;
// trstctl only emits one outbox-delivered alert to the gateway.
package sms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/secrettext"
)

// Channel satisfies the notification template.
var _ notify.Notifier = (*Channel)(nil)

// HTTPDoer is the minimal HTTP client seam: production uses netsec.SafeClient, tests
// inject the double's client.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Channel delivers alerts to an SMS gateway. The bearer token is held as bytes and
// only converted at the HTTP header edge.
type Channel struct {
	endpoint               string
	from                   string
	to                     []string
	token                  []byte
	doer                   HTTPDoer
	skipEndpointValidation bool
}

// Option configures a Channel.
type Option func(*Channel)

// WithHTTPClient injects the HTTP doer.
func WithHTTPClient(d HTTPDoer) Option {
	return func(c *Channel) {
		c.doer = d
		c.skipEndpointValidation = true
	}
}

// New returns an SMS channel that POSTs alerts to endpoint. The endpoint is expected
// to translate the request into the operator's SMS provider.
func New(endpoint, from string, to []string, token []byte, opts ...Option) *Channel {
	c := &Channel{
		endpoint: endpoint,
		from:     from,
		to:       append([]string(nil), to...),
		token:    secrettext.Clone(token),
		doer:     netsec.SafeClient(10 * time.Second),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Name identifies the channel.
func (c *Channel) Name() string { return "sms" }

// Notify posts one SMS alert request. Delivery is at-least-once via the notification
// outbox, so the gateway must tolerate a retry of the same alert.
func (c *Channel) Notify(ctx context.Context, alert notify.Alert) error {
	if !c.skipEndpointValidation {
		if err := netsec.ValidatePublicHTTPSURL(c.endpoint); err != nil {
			return fmt.Errorf("sms: validate endpoint: %w", err)
		}
	}
	body, err := json.Marshal(request{
		From:      c.from,
		To:        append([]string(nil), c.to...),
		Text:      notify.FormatMessage(alert),
		TenantID:  alert.TenantID,
		Severity:  alert.Severity,
		Kind:      alert.Kind,
		Subject:   alert.Subject,
		AlertID:   alert.CertificateID,
		NotAfter:  alert.NotAfter,
		OwnerName: alert.OwnerName,
	})
	if err != nil {
		return fmt.Errorf("sms: encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("sms: build request: %w", scrubEndpoint(err, c.endpoint))
	}
	req.Header.Set("Content-Type", "application/json")
	if len(c.token) > 0 {
		req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", c.token))
	}

	resp, err := c.doer.Do(req)
	if err != nil {
		return fmt.Errorf("sms: post alert: %w", scrubEndpoint(err, c.endpoint))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return readError(resp)
	}
	drain(resp)
	return nil
}

func readError(resp *http.Response) error {
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return &apiError{status: resp.StatusCode, body: strings.TrimSpace(string(msg))}
}

func scrubEndpoint(err error, endpoint string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, netsec.ErrSSRFBlocked) {
		return netsec.ErrSSRFBlocked
	}
	if endpoint != "" && strings.Contains(err.Error(), endpoint) {
		return errRedacted
	}
	return err
}

var errRedacted = errors.New("request to sms endpoint failed (details withheld to avoid leaking the endpoint URL)")

func drain(resp *http.Response) { _, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) }

type request struct {
	From      string    `json:"from,omitempty"`
	To        []string  `json:"to"`
	Text      string    `json:"text"`
	TenantID  string    `json:"tenant_id,omitempty"`
	Severity  string    `json:"severity,omitempty"`
	Kind      string    `json:"kind,omitempty"`
	Subject   string    `json:"subject,omitempty"`
	AlertID   string    `json:"alert_id,omitempty"`
	NotAfter  time.Time `json:"not_after,omitempty"`
	OwnerName string    `json:"owner_name,omitempty"`
}

type apiError struct {
	status int
	body   string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("sms: status %d: %s", e.status, e.body)
}
