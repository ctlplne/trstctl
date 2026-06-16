// Package teams is the Microsoft Teams notification channel (S10.4), built from the
// same notification template as the other channels: it implements notify.Notifier and
// self-validates against the notify.Conform harness, the notification analogue of the
// DNS-01 and connector conformance suites.
//
// A Teams "incoming webhook" accepts a legacy MessageCard JSON document posted to a
// per-channel webhook URL; Teams renders the card in the target channel. This channel
// POSTs a minimal MessageCard whose text is notify.FormatMessage(alert) — the same
// plain-text line every chat channel reuses — and treats any 2xx as delivered.
//
// The webhook URL is a secret: it is a bearer capability (anyone holding it can post to
// the channel), so it is carried opaquely, never logged, and never written into error
// text. On a non-2xx response the error surfaces the response body (which is the Teams
// error message and does not echo the URL), never the URL itself (AN-8 lineage — the
// same rule the Cloudflare provider follows for its API token).
//
// No cryptographic operation happens here, so this package imports no crypto/* (AN-3);
// there is nothing to route through the crypto boundary. When the channel is driven from
// the notification dispatcher, the outbox provides at-least-once delivery (AN-6) and
// Notify is safe to call more than once for the same alert.
package teams

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/notify"
)

// Channel satisfies the notification template.
var _ notify.Notifier = (*Channel)(nil)

// HTTPDoer is the minimal HTTP client seam: production uses http.DefaultClient, tests
// inject the double's client.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Channel delivers alerts to a Microsoft Teams channel via an incoming-webhook URL. The
// URL is a secret bearer capability: it is held opaquely and never logged or surfaced in
// errors (AN-8).
type Channel struct {
	webhookURL string
	doer       HTTPDoer
}

// Option configures a Channel.
type Option func(*Channel)

// WithHTTPClient injects the HTTP doer (tests pass the double's client).
func WithHTTPClient(d HTTPDoer) Option {
	return func(c *Channel) { c.doer = d }
}

// New returns a Teams channel that posts to webhookURL. The URL is the per-channel
// incoming-webhook secret and is never logged or echoed in errors.
func New(webhookURL string, opts ...Option) *Channel {
	c := &Channel{
		webhookURL: webhookURL,
		doer:       http.DefaultClient,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Name identifies the channel.
func (c *Channel) Name() string { return "msteams" }

// Notify delivers the alert as a Teams MessageCard. It POSTs the card to the webhook
// URL; any 2xx is success. A non-2xx response yields an error carrying the Teams
// response body — which is the service's error message and never echoes the webhook URL
// (AN-8). Delivery is at-least-once (the outbox may retry), so this is safe to call more
// than once for the same alert and never panics on a sparse alert.
func (c *Channel) Notify(ctx context.Context, alert notify.Alert) error {
	body, err := json.Marshal(messageCard{
		Type:    "MessageCard",
		Context: "http://schema.org/extensions",
		Summary: "trstctl alert",
		Text:    notify.FormatMessage(alert),
	})
	if err != nil {
		return fmt.Errorf("msteams: encode card: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.webhookURL, bytes.NewReader(body))
	if err != nil {
		// http.NewRequestWithContext can echo the raw URL in its error; scrub it so
		// the webhook secret never reaches the caller (AN-8).
		return fmt.Errorf("msteams: build request: %w", scrubURL(err, c.webhookURL))
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doer.Do(req)
	if err != nil {
		// Transport errors (url.Error) carry the request URL; scrub it (AN-8).
		return fmt.Errorf("msteams: post alert: %w", scrubURL(err, c.webhookURL))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return readError(resp)
	}
	drain(resp)
	return nil
}

// readError turns a non-2xx response into a postError whose text is the response body.
// The Teams error body is the service's own message and never echoes the webhook URL, so
// surfacing it does not leak the secret (AN-8).
func readError(resp *http.Response) error {
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return &postError{status: resp.StatusCode, body: strings.TrimSpace(string(msg))}
}

// scrubURL guards against the standard library embedding the webhook URL in an error
// (for example *url.Error wraps the request URL): if the secret appears in the error
// text, replace the whole error with a fixed, secret-free message (AN-8).
func scrubURL(err error, secret string) error {
	if err == nil {
		return nil
	}
	if secret != "" && strings.Contains(err.Error(), secret) {
		return errRedacted
	}
	return err
}

// errRedacted is the stand-in returned when an underlying error would otherwise leak the
// webhook URL.
var errRedacted = errors.New("request to msteams webhook failed (details withheld to avoid leaking the webhook URL)")

// drain consumes and discards a successful response body so the connection can be reused.
func drain(resp *http.Response) { _, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) }

// messageCard is the legacy Teams MessageCard wire shape this channel posts.
type messageCard struct {
	Type    string `json:"@type"`
	Context string `json:"@context"`
	Summary string `json:"summary"`
	Text    string `json:"text"`
}

// postError is a non-2xx Teams response. Its body is the service's error text and never
// carries the webhook URL (AN-8).
type postError struct {
	status int
	body   string
}

func (e *postError) Error() string {
	return fmt.Sprintf("msteams: status %d: %s", e.status, e.body)
}
