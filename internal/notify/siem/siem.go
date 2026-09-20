// SPDX-License-Identifier: BUSL-1.1

// Package siem is the SIEM notification channel. It emits security-alert JSON to an
// operator-managed collector such as Splunk HEC, Sentinel, QRadar, or a forwarding
// gateway. The collector-specific mapping lives outside trstctl; this package owns
// the outbox-backed delivery edge.
package siem

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
	"trstctl.com/trstctl/internal/secrettext"
)

// Channel satisfies the notification template.
var _ notify.Notifier = (*Channel)(nil)

// HTTPDoer is the minimal HTTP client seam.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Channel delivers alert events to a SIEM collector. The token is held as bytes and
// only converted when setting the HTTP Authorization header.
type Channel struct {
	endpoint               string
	token                  []byte
	source                 string
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

// WithSource sets the source field carried in each SIEM event.
func WithSource(source string) Option {
	return func(c *Channel) { c.source = source }
}

// New returns a SIEM channel that POSTs structured alert events to endpoint.
func New(endpoint string, token []byte, opts ...Option) *Channel {
	c := &Channel{
		endpoint: endpoint,
		token:    secrettext.Clone(token),
		source:   "trstctl",
		doer:     netsec.SafeClient(10 * time.Second),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Name identifies the channel.
func (c *Channel) Name() string { return "siem" }

// Notify posts one structured event. Delivery is at-least-once via the notification
// outbox, so collectors should deduplicate using tenant_id plus alert identifiers.
func (c *Channel) Notify(ctx context.Context, alert notify.Alert) error {
	if !c.skipEndpointValidation {
		if err := netsec.ValidatePublicHTTPSURL(c.endpoint); err != nil {
			return fmt.Errorf("siem: validate endpoint: %w", err)
		}
	}
	body, err := json.Marshal(event{
		Time:      time.Now().UTC(),
		Source:    c.source,
		EventType: alert.Kind,
		Message:   notify.FormatMessage(alert),
		Severity:  alert.Severity,
		TenantID:  alert.TenantID,
		Alert:     alert,
	})
	if err != nil {
		return fmt.Errorf("siem: encode event: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("siem: build request: %w", scrubEndpoint(err, c.endpoint))
	}
	req.Header.Set("Content-Type", "application/json")
	if len(c.token) > 0 {
		req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", c.token))
	}

	resp, err := c.doer.Do(req)
	if err != nil {
		return fmt.Errorf("siem: post event: %w", scrubEndpoint(err, c.endpoint))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return readError(resp)
	}
	drain(resp)
	return nil
}

func readError(resp *http.Response) error {
	_ = secret.DrainBounded(resp.Body, 4096)
	return &apiError{status: resp.StatusCode}
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

var errRedacted = errors.New("request to siem endpoint failed (details withheld to avoid leaking the endpoint URL)")

func drain(resp *http.Response) { _ = secret.DrainBounded(resp.Body, 1<<20) }

type event struct {
	Time      time.Time    `json:"time"`
	Source    string       `json:"source"`
	EventType string       `json:"event_type,omitempty"`
	Message   string       `json:"message"`
	Severity  string       `json:"severity,omitempty"`
	TenantID  string       `json:"tenant_id,omitempty"`
	Alert     notify.Alert `json:"alert"`
}

type apiError struct {
	status int
}

func (e *apiError) Error() string {
	return fmt.Sprintf("siem: status %d (response body redacted)", e.status)
}
