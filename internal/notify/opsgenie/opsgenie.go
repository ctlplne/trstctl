// Package opsgenie is the OpsGenie notification channel (S10.6), built from the same
// notification template as every other channel: the notify.Notifier interface plus the
// notify.Conform harness (the notification analogue of the connector SDK, S5.5). It
// delivers an Alert by creating an OpsGenie alert through the Alert API over HTTPS,
// authenticated with a scoped API key.
//
// OpsGenie's Alert API authenticates with an API key carried in the Authorization header
// in the GenieKey scheme (Authorization: GenieKey <key>) — the header analogue of
// Cloudflare's bearer token, not a body-embedded routing key like PagerDuty. The key is
// opaque to this package, never logged, and sealed at rest by the caller via the platform
// secret store (AN-8); the error text returned to callers is the API response body, which
// never echoes the key. No cryptographic operation happens in this package, so it imports
// no crypto/* (AN-3) — there is nothing to route through the crypto boundary here.
//
// A channel does exactly one thing — POST a create-alert request to one endpoint — and
// makes no other outbound calls (the least-privilege pattern of the connector SDK, S5.5).
//
// Delivery is at-least-once (the outbox may retry, AN-6): creating the same alert more
// than once is acceptable, and the message is rendered with notify.FormatMessage so every
// channel reuses one plain-text summary.
package opsgenie

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/notify"
)

// defaultEndpoint is the public OpsGenie Alert API create-alert endpoint.
const defaultEndpoint = "https://api.opsgenie.com/v2/alerts"

// Channel satisfies the notification template.
var _ notify.Notifier = (*Channel)(nil)

// HTTPDoer is the minimal HTTP client seam: production uses http.DefaultClient, tests
// inject the double's client.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Channel is an OpsGenie Alert API notification channel bound to one API key. The key is
// opaque to this package, never logged, and sealed at rest by the caller (AN-8).
type Channel struct {
	apiKey   string // OpsGenie Alert API key; carried as Authorization: GenieKey <key>; never logged (AN-8)
	endpoint string // create-alert URL
	doer     HTTPDoer
}

// Option configures a Channel.
type Option func(*Channel)

// WithEndpoint overrides the OpsGenie Alert API endpoint (for tests or alternate
// gateways, e.g. the EU region host).
func WithEndpoint(endpoint string) Option {
	return func(c *Channel) { c.endpoint = endpoint }
}

// WithHTTPClient injects the HTTP doer (tests pass the double's client).
func WithHTTPClient(d HTTPDoer) Option {
	return func(c *Channel) { c.doer = d }
}

// New returns an OpsGenie channel that creates alerts authenticated with apiKey. The
// endpoint defaults to the public Alert API create-alert endpoint.
func New(apiKey string, opts ...Option) *Channel {
	c := &Channel{
		apiKey:   apiKey,
		endpoint: defaultEndpoint,
		doer:     http.DefaultClient,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Name identifies the channel.
func (c *Channel) Name() string { return "opsgenie" }

// Notify creates an OpsGenie alert for the alert. It POSTs a create-alert request whose
// message is notify.FormatMessage(alert) and whose description is alert.Detail,
// authenticated with the Authorization: GenieKey <key> header. A 2xx response is success;
// any other status returns an error carrying the response body (never the API key, AN-8).
// Creating is safe to repeat, so an outbox retry (AN-6) is harmless.
func (c *Channel) Notify(ctx context.Context, alert notify.Alert) error {
	body, err := json.Marshal(createAlertRequest{
		Message:     notify.FormatMessage(alert),
		Description: alert.Detail,
	})
	if err != nil {
		return fmt.Errorf("opsgenie: encode alert: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	// The API key is attached here and nowhere else; it is never written to logs or error
	// text (AN-8).
	req.Header.Set("Authorization", "GenieKey "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doer.Do(req)
	if err != nil {
		return fmt.Errorf("opsgenie: create alert: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return readError(resp)
	}
	drain(resp)
	return nil
}

// readError turns a non-2xx response into an apiError whose text is the response body.
// OpsGenie error bodies describe the rejection and never echo the request API key, so
// surfacing them does not leak credentials (AN-8).
func readError(resp *http.Response) error {
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return &apiError{status: resp.StatusCode, body: strings.TrimSpace(string(msg))}
}

// drain consumes and discards a successful response body so the connection can be reused.
func drain(resp *http.Response) { _, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) }

// createAlertRequest is the OpsGenie Alert API create-alert body. The API key is not part
// of the body — it rides the Authorization header — so it never appears here (AN-8).
type createAlertRequest struct {
	Message     string `json:"message"`
	Description string `json:"description,omitempty"`
}

// apiError is a non-2xx OpsGenie response. Its body is the API error text and never
// carries the request API key (AN-8).
type apiError struct {
	status int
	body   string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("opsgenie: status %d: %s", e.status, e.body)
}
