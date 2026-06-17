// Package pagerduty is the PagerDuty notification channel (S10.5), built from the same
// notification template as every other channel: the notify.Notifier interface plus the
// notify.Conform harness (the notification analogue of the connector SDK, S5.5). It
// delivers an Alert by triggering a PagerDuty incident through the Events API v2 enqueue
// endpoint over HTTPS, authenticated with a scoped integration routing key.
//
// PagerDuty's Events API v2 does not use a bearer token; the routing key is carried in
// the JSON body as routing_key and selects the service the event lands on. The key is
// opaque to this package, never logged, and sealed at rest by the caller via the
// platform secret store (AN-8); the error text returned to callers is the API response
// body, which never echoes the routing key. No cryptographic operation happens in this
// package, so it imports no crypto/* (AN-3) — there is nothing to route through the
// crypto boundary here.
//
// A channel does exactly one thing — POST a trigger event to one endpoint — and makes no
// other outbound calls (the least-privilege pattern of the connector SDK, S5.5).
//
// Delivery is at-least-once (the outbox may retry, AN-6): triggering the same alert more
// than once is acceptable, and the message body is rendered with notify.FormatMessage so
// every channel reuses one plain-text summary.
package pagerduty

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
)

// defaultEndpoint is the public PagerDuty Events API v2 enqueue endpoint.
const defaultEndpoint = "https://events.pagerduty.com/v2/enqueue"

// Channel satisfies the notification template.
var _ notify.Notifier = (*Channel)(nil)

// HTTPDoer is the minimal HTTP client seam: production uses netsec.SafeClient, tests
// inject the double's client.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Channel is a PagerDuty Events API v2 notification channel bound to one routing key.
// The routing key is opaque to this package, never logged, and sealed at rest by the
// caller (AN-8).
type Channel struct {
	routingKey             string // Events API v2 integration routing key; never logged (AN-8)
	endpoint               string // enqueue URL
	doer                   HTTPDoer
	skipEndpointValidation bool
}

// Option configures a Channel.
type Option func(*Channel)

// WithEndpoint overrides the PagerDuty enqueue endpoint (for tests or alternate
// gateways).
func WithEndpoint(endpoint string) Option {
	return func(c *Channel) { c.endpoint = endpoint }
}

// WithHTTPClient injects the HTTP doer (tests pass the double's client).
func WithHTTPClient(d HTTPDoer) Option {
	return func(c *Channel) {
		c.doer = d
		c.skipEndpointValidation = true
	}
}

// New returns a PagerDuty channel that triggers incidents on the service selected by
// routingKey. The endpoint defaults to the public Events API v2 enqueue endpoint. The
// default delivery path accepts only public HTTPS endpoints and uses the shared
// SSRF-safe HTTP client.
func New(routingKey string, opts ...Option) *Channel {
	c := &Channel{
		routingKey: routingKey,
		endpoint:   defaultEndpoint,
		doer:       netsec.SafeClient(10 * time.Second),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Name identifies the channel.
func (c *Channel) Name() string { return "pagerduty" }

// Notify triggers a PagerDuty incident for the alert. It POSTs an Events API v2 trigger
// event whose payload summary is notify.FormatMessage(alert). A 2xx response is success;
// any other status returns an error carrying the response body (never the routing key,
// AN-8). Triggering is safe to repeat, so an outbox retry (AN-6) is harmless.
func (c *Channel) Notify(ctx context.Context, alert notify.Alert) error {
	if !c.skipEndpointValidation {
		if err := netsec.ValidatePublicHTTPSURL(c.endpoint); err != nil {
			return fmt.Errorf("pagerduty: validate endpoint: %w", err)
		}
	}
	body, err := json.Marshal(eventRequest{
		RoutingKey:  c.routingKey,
		EventAction: "trigger",
		Payload: eventPayload{
			Summary:  notify.FormatMessage(alert),
			Source:   "trstctl",
			Severity: "warning",
		},
	})
	if err != nil {
		return fmt.Errorf("pagerduty: encode event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("pagerduty: build request: %w", scrubEndpoint(err, c.endpoint))
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doer.Do(req)
	if err != nil {
		return fmt.Errorf("pagerduty: enqueue event: %w", scrubEndpoint(err, c.endpoint))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return readError(resp)
	}
	drain(resp)
	return nil
}

// readError turns a non-2xx response into an apiError whose text is the response body.
// PagerDuty error bodies describe the rejection and never echo the request routing key,
// so surfacing them does not leak credentials (AN-8).
func readError(resp *http.Response) error {
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return &apiError{status: resp.StatusCode, body: strings.TrimSpace(string(msg))}
}

// drain consumes and discards a successful response body so the connection can be reused.
func drain(resp *http.Response) { _, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) }

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

var errRedacted = errors.New("request to pagerduty endpoint failed (details withheld to avoid leaking the endpoint URL)")

// eventRequest is the Events API v2 enqueue body. RoutingKey selects the target service;
// it is set here and nowhere else and is never written to logs or error text (AN-8).
type eventRequest struct {
	RoutingKey  string       `json:"routing_key"`
	EventAction string       `json:"event_action"`
	Payload     eventPayload `json:"payload"`
}

// eventPayload is the alert payload of an Events API v2 event.
type eventPayload struct {
	Summary  string `json:"summary"`
	Source   string `json:"source"`
	Severity string `json:"severity"`
}

// apiError is a non-2xx PagerDuty response. Its body is the API error text and never
// carries the request routing key (AN-8).
type apiError struct {
	status int
	body   string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("pagerduty: status %d: %s", e.status, e.body)
}
