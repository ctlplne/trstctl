// SPDX-License-Identifier: MPL-2.0

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
// secret store (AN-8); remote response bodies are redacted on every error path because a
// compromised gateway could echo the key. The deterministic retry alias is hashed only
// through internal/crypto, preserving the single cryptographic boundary (AN-3).
//
// A channel does exactly one thing — POST a create-alert request to one endpoint — and
// makes no other outbound calls (the least-privilege pattern of the connector SDK, S5.5).
//
// Delivery is at-least-once (the outbox may retry, AN-6). Every request carries a
// deterministic alias derived from the tenant-scoped alert, so OpsGenie collapses a
// retry into the same alert rather than opening a duplicate.
package opsgenie

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/secrettext"
)

// defaultEndpoint is the public OpsGenie Alert API create-alert endpoint.
const defaultEndpoint = "https://api.opsgenie.com/v2/alerts"

// Channel satisfies the notification template.
var _ notify.Notifier = (*Channel)(nil)

// HTTPDoer is the minimal HTTP client seam: production uses netsec.SafeClient, tests
// inject the double's client.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Channel is an OpsGenie Alert API notification channel bound to one API key. The key is
// opaque to this package, never logged, held in locked memory, and wiped by Close (AN-8).
type Channel struct {
	apiKey                 *secret.Buffer // OpsGenie API key; locked, non-dumpable, and wiped (AN-8)
	endpoint               string         // create-alert URL
	doer                   HTTPDoer
	skipEndpointValidation bool
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
	return func(c *Channel) {
		c.doer = d
		c.skipEndpointValidation = true
	}
}

// New returns an OpsGenie channel that creates alerts authenticated with apiKey. The
// credential is copied into locked, non-dumpable memory and must be released with Close.
// The endpoint defaults to the public Alert API create-alert endpoint. The default
// delivery path accepts only public HTTPS endpoints and uses the shared SSRF-safe client.
func New(apiKey []byte, opts ...Option) (*Channel, error) {
	if err := validateAPIKey(apiKey); err != nil {
		return nil, err
	}
	key, err := secret.NewFrom(apiKey)
	if err != nil {
		return nil, fmt.Errorf("opsgenie: protect API key: %w", err)
	}
	c := &Channel{
		apiKey:   key,
		endpoint: defaultEndpoint,
		doer:     netsec.SafeClient(10 * time.Second),
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

func validateAPIKey(key []byte) error {
	if len(key) == 0 {
		return errors.New("opsgenie: API key is required")
	}
	if len(key) > 255 {
		return errors.New("opsgenie: API key is too long")
	}
	// OpsGenie API keys are UUID-like opaque ASCII tokens. Restricting the
	// accepted bytes before the key enters locked memory prevents a credential
	// from injecting a second HTTP header when it is framed as GenieKey <key>.
	for _, b := range key {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-' || b == '_' {
			continue
		}
		return errors.New("opsgenie: API key contains a non-token byte")
	}
	return nil
}

// Close wipes and releases the API key. It is safe to call more than once.
func (c *Channel) Close() {
	if c != nil && c.apiKey != nil {
		c.apiKey.Destroy()
	}
}

// Name identifies the channel.
func (c *Channel) Name() string { return "opsgenie" }

// Notify creates an OpsGenie alert for the alert. It POSTs a create-alert request whose
// message is notify.FormatMessage(alert) and whose description is alert.Detail,
// authenticated with the Authorization: GenieKey <key> header. Only the vendor's exact
// 202 acceptance envelope is success; remote error bodies are discarded (AN-8). The
// deterministic alias makes an outbox retry (AN-6) address the same alert.
func (c *Channel) Notify(ctx context.Context, alert notify.Alert) error {
	if !c.skipEndpointValidation {
		if err := netsec.ValidatePublicHTTPSURL(c.endpoint); err != nil {
			return fmt.Errorf("opsgenie: validate endpoint: %w", err)
		}
	}
	if c.apiKey == nil || c.apiKey.Len() == 0 {
		return errors.New("opsgenie: API key is unavailable")
	}
	alias, err := alertAlias(alert)
	if err != nil {
		return fmt.Errorf("opsgenie: derive alert alias: %w", err)
	}
	body, err := json.Marshal(createAlertRequest{
		Message:     truncateUTF8(notify.FormatMessage(alert), 130),
		Alias:       alias,
		Description: truncateUTF8(alert.Detail, 15000),
		Source:      "trstctl",
		Entity:      truncateUTF8(nonempty(alert.CertificateID, alert.Subject), 512),
		Priority:    opsGeniePriority(alert.Severity),
	})
	if err != nil {
		return fmt.Errorf("opsgenie: encode alert: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("opsgenie: build request: %w", scrubEndpoint(err, c.endpoint))
	}
	// The API key is attached here and nowhere else; it is never written to logs or error
	// text (AN-8).
	req.Header.Set("Authorization", secrettext.Prefixed("GenieKey ", c.apiKey.Bytes()))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.doer.Do(req)
	if err != nil {
		return fmt.Errorf("opsgenie: create alert: %w", scrubEndpoint(err, c.endpoint))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusAccepted {
		return readError(resp)
	}
	responseBody, err := secret.ReadBounded(resp.Body, 1<<20)
	if err != nil {
		return errors.New("opsgenie: read accepted alert response (details redacted)")
	}
	defer secret.Wipe(responseBody)
	var accepted struct {
		Result    json.RawMessage `json:"result"`
		RequestID json.RawMessage `json:"requestId"`
	}
	defer func() {
		secret.Wipe(accepted.Result)
		secret.Wipe(accepted.RequestID)
	}()
	if err := json.Unmarshal(responseBody, &accepted); err != nil {
		return errors.New("opsgenie: decode accepted alert response (details redacted)")
	}
	if !bytes.Equal(accepted.Result, []byte(`"Request will be processed"`)) || !nonemptyJSONString(accepted.RequestID) {
		return errors.New("opsgenie: Alert API returned an unexpected acceptance receipt")
	}
	return nil
}

func alertAlias(alert notify.Alert) (string, error) {
	encoded, err := json.Marshal(alert)
	if err != nil {
		return "", err
	}
	return "trstctl-" + crypto.SHA256Hex(encoded), nil
}

func opsGeniePriority(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case notify.AlertSeverityCritical:
		return "P1"
	case notify.AlertSeverityWarning:
		return "P2"
	default:
		return "P3"
	}
}

func truncateUTF8(value string, maxCharacters int) string {
	if maxCharacters <= 0 {
		return value
	}
	count := 0
	for byteIndex := range value {
		if count == maxCharacters {
			return value[:byteIndex]
		}
		count++
	}
	return value
}

func nonempty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// nonemptyJSONString checks the vendor request-id receipt without converting
// attacker-controlled response bytes into an immutable Go string. The exact
// identifier is not retained; the RawMessage backing bytes are wiped by Notify.
func nonemptyJSONString(value []byte) bool {
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
		return false
	}
	for _, b := range value[1 : len(value)-1] {
		if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
			return true
		}
	}
	return false
}

// readError deliberately does not surface the remote body. A compromised gateway
// could echo the API key; returning only the status keeps authority material out of
// logs while retaining the retryable failure signal.
func readError(resp *http.Response) error {
	_ = secret.DrainBounded(resp.Body, 4<<10)
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

var errRedacted = errors.New("request to opsgenie endpoint failed (details withheld to avoid leaking the endpoint URL)")

// createAlertRequest is the OpsGenie Alert API create-alert body. The API key is not part
// of the body — it rides the Authorization header — so it never appears here (AN-8).
type createAlertRequest struct {
	Message     string `json:"message"`
	Alias       string `json:"alias"`
	Description string `json:"description,omitempty"`
	Source      string `json:"source"`
	Entity      string `json:"entity,omitempty"`
	Priority    string `json:"priority"`
}

// apiError is a redacted non-2xx OpsGenie response.
type apiError struct {
	status int
}

func (e *apiError) Error() string {
	return fmt.Sprintf("opsgenie: status %d (response body redacted)", e.status)
}
