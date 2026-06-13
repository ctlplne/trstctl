// Package slack is the Slack notification channel (S10.3), the first concrete
// notify.Notifier built on the channel template (S10.2): notify already defines the
// Alert vocabulary, the Notifier interface every channel implements, the shared
// FormatMessage renderer, and the Conform self-validation harness; this delivers an
// alert to Slack by POSTing an incoming-webhook payload.
//
// A Slack incoming webhook is a single secret URL: knowing the URL is sufficient to
// post into the channel, so the URL is both the post target and the credential. It is
// carried as an opaque string, is never logged, and is sealed at rest by the caller via
// the platform secret store (AN-8). Error text returned to callers is the Slack response
// body (e.g. "invalid_token", "no_service"), which never echoes the webhook URL, so
// surfacing it cannot leak the credential. No cryptographic operation happens in this
// package, so it imports no crypto/* (AN-3) — there is nothing to route through the
// crypto boundary here.
//
// Delivery is at-least-once: a notification.* outbox entry may be retried (AN-6), and
// Notify is a single idempotent POST, safe to call more than once for the same alert and
// safe on a sparse alert (FormatMessage tolerates empty fields).
package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"trustctl.io/trustctl/internal/notify"
)

// Channel satisfies the notification channel template.
var _ notify.Notifier = (*Channel)(nil)

// HTTPDoer is the minimal HTTP client seam: production uses http.DefaultClient, tests
// inject the double's client.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Channel is a Slack incoming-webhook notification channel. The webhook URL is the post
// target and the credential; it is opaque to this package, never logged, and sealed at
// rest by the caller (AN-8).
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

// New returns a Slack channel that posts to webhookURL. The webhook URL is the secret;
// callers supply it from the platform secret store.
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
func (c *Channel) Name() string { return "slack" }

// Notify delivers the alert as a Slack message. It renders the alert with the shared
// FormatMessage (so every channel produces the same line) and POSTs {"text": ...} to
// the webhook. Any 2xx is success; a non-2xx is returned as an error whose text is the
// Slack response body — never the webhook URL (AN-8). Delivery is at-least-once, so a
// retried POST of the same alert simply posts the same message again (AN-6).
func (c *Channel) Notify(ctx context.Context, alert notify.Alert) error {
	body, err := json.Marshal(payload{Text: notify.FormatMessage(alert)})
	if err != nil {
		return fmt.Errorf("slack: encode message: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.webhookURL, bytes.NewReader(body))
	if err != nil {
		// http.NewRequestWithContext can echo the raw URL in its error; wrap with a
		// fixed message so the webhook secret never reaches the caller (AN-8).
		return fmt.Errorf("slack: build request: %w", scrubURL(err, c.webhookURL))
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doer.Do(req)
	if err != nil {
		// Transport errors (url.Error) carry the request URL; scrub it (AN-8).
		return fmt.Errorf("slack: post message: %w", scrubURL(err, c.webhookURL))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return readError(resp)
	}
	drain(resp)
	return nil
}

// readError turns a non-2xx Slack response into an apiError whose text is the response
// body. Slack webhook error bodies are short tokens like "invalid_token" or "no_service"
// and never echo the request URL, so surfacing them does not leak the webhook (AN-8).
func readError(resp *http.Response) error {
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return &apiError{status: resp.StatusCode, body: strings.TrimSpace(string(msg))}
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
var errRedacted = errors.New("request to slack webhook failed (details withheld to avoid leaking the webhook URL)")

// drain consumes and discards a successful response body so the connection can be reused.
func drain(resp *http.Response) { _, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) }

// payload is the Slack incoming-webhook request body. text is the only field a webhook
// requires; FormatMessage produces it.
type payload struct {
	Text string `json:"text"`
}

// apiError is a non-2xx Slack response. Its body is the Slack error text and never
// carries the webhook URL (AN-8).
type apiError struct {
	status int
	body   string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("slack: status %d: %s", e.status, e.body)
}
