// Package webhook is the generic HMAC-signed webhook notification channel (S10.7),
// built from the same notification template as every other channel: it implements
// notify.Notifier and self-validates against the notify.Conform harness (the
// notification analogue of the connector SDK, S5.5). It delivers an Alert by POSTing
// the alert as JSON to a caller-supplied endpoint over HTTP, signing the request body
// with HMAC-SHA256 so the receiver can authenticate it.
//
// Unlike the chat channels (Slack, Teams) whose secret is the webhook URL itself, the
// secret here is a shared HMAC key: the channel computes
// sig := hex(HMAC-SHA256(secret, body)) over the exact JSON body it sends and presents
// it as the X-Trustctl-Signature: sha256=<sig> header. A receiver that holds the same
// key recomputes the MAC over the bytes it received and rejects any request whose
// signature does not match — the standard "signed webhook" handshake. Because the MAC
// covers the body, a tampered payload fails verification.
//
// The secret is the HMAC key and is held as []byte, never a string (AN-8): Go's GC can
// freely copy a string, so key material lives in a byte slice the caller can later
// zero. It is the channel's credential — it is never logged, never written into error
// text, and never placed in the request (only the derived signature is). On a non-2xx
// response the error surfaces the response body (the receiver's own error message,
// which does not contain the key), never the key or the URL (AN-8 lineage — the same
// rule the Cloudflare provider follows for its API token and the Teams channel for its
// URL).
//
// The HMAC is computed through internal/crypto.HMACSHA256, the AN-3 crypto boundary, so
// this package imports no crypto/* directly — only encoding/hex to render the digest.
// When the channel is driven from the notification dispatcher, the outbox provides
// at-least-once delivery (AN-6) and Notify is safe to call more than once for the same
// alert; signing is deterministic, so a re-delivered alert produces the identical
// signature.
package webhook

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"trustctl.io/trustctl/internal/crypto"
	"trustctl.io/trustctl/internal/notify"
)

// signatureHeader carries the hex HMAC-SHA256 of the request body, prefixed with the
// algorithm: X-Trustctl-Signature: sha256=<hex>.
const signatureHeader = "X-Trustctl-Signature"

// Channel satisfies the notification template.
var _ notify.Notifier = (*Channel)(nil)

// HTTPDoer is the minimal HTTP client seam: production uses http.DefaultClient, tests
// inject the double's client.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Channel delivers alerts to a generic HTTP endpoint, signing each request body with
// HMAC-SHA256 under a shared secret so the receiver can authenticate it. The secret is
// the HMAC key: it is held as []byte (AN-8), never logged, and never echoed in errors;
// only the derived signature ever leaves the process.
type Channel struct {
	url    string
	secret []byte // HMAC key; never logged, never surfaced in errors (AN-8)
	doer   HTTPDoer
}

// Option configures a Channel.
type Option func(*Channel)

// WithHTTPClient injects the HTTP doer (tests pass the double's client).
func WithHTTPClient(d HTTPDoer) Option {
	return func(c *Channel) { c.doer = d }
}

// New returns a webhook channel that POSTs alerts to url, signing each body with secret
// (the HMAC key). The secret is retained by reference; callers that zero their key
// material (AN-8) must not zero it while the channel is in use.
func New(url string, secret []byte, opts ...Option) *Channel {
	c := &Channel{
		url:    url,
		secret: secret,
		doer:   http.DefaultClient,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Name identifies the channel.
func (c *Channel) Name() string { return "webhook" }

// Notify delivers the alert as a signed JSON POST. It marshals the Alert, computes
// sig := hex(HMAC-SHA256(secret, body)) over the exact bytes it sends (routed through
// the crypto boundary, AN-3), attaches it as X-Trustctl-Signature: sha256=<sig>, and
// POSTs the body to the endpoint. Any 2xx is success; a non-2xx response yields an error
// carrying the receiver's response body — never the secret or the URL (AN-8). Delivery
// is at-least-once (the outbox may retry), so this is safe to call more than once for
// the same alert; the signature is deterministic and never panics on a sparse alert.
func (c *Channel) Notify(ctx context.Context, alert notify.Alert) error {
	body, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("webhook: encode alert: %w", err)
	}

	// Sign the exact bytes that go on the wire so the receiver, recomputing the MAC
	// over what it received, gets the same digest. The HMAC routes through the crypto
	// boundary (AN-3); only the hex signature — never the key — is emitted.
	sig := hex.EncodeToString(crypto.HMACSHA256(c.secret, body))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		// NewRequestWithContext only fails on a malformed method/URL; the URL is a
		// secret-adjacent capability, so surface only the cause's class, not the URL.
		return fmt.Errorf("webhook: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(signatureHeader, "sha256="+sig)

	resp, err := c.doer.Do(req)
	if err != nil {
		// A transport error from net/http can embed the request URL in its text, so it
		// is not surfaced here; only a fixed, URL-free message is returned (AN-8).
		return fmt.Errorf("webhook: post alert: transport error")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return readError(resp)
	}
	drain(resp)
	return nil
}

// readError turns a non-2xx response into a postError whose text is the response body.
// The receiver's error body is its own message and never carries the HMAC key (the key
// never leaves this process), so surfacing it does not leak the secret (AN-8).
func readError(resp *http.Response) error {
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return &postError{status: resp.StatusCode, body: string(bytes.TrimSpace(msg))}
}

// drain consumes and discards a successful response body so the connection can be reused.
func drain(resp *http.Response) { _, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) }

// postError is a non-2xx webhook response. Its body is the receiver's error text and
// never carries the HMAC key (AN-8).
type postError struct {
	status int
	body   string
}

func (e *postError) Error() string {
	return fmt.Sprintf("webhook: status %d: %s", e.status, e.body)
}
