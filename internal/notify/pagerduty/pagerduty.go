// SPDX-License-Identifier: MPL-2.0

// Package pagerduty is the PagerDuty notification channel (S10.5), built from the same
// notification template as every other channel: the notify.Notifier interface plus the
// notify.Conform harness (the notification analogue of the connector SDK, S5.5). It
// delivers an Alert by triggering a PagerDuty incident through the Events API v2 enqueue
// endpoint over HTTPS, authenticated with a scoped integration routing key.
//
// PagerDuty's Events API v2 does not use a bearer token; the routing key is carried in
// the JSON body as routing_key and selects the service the event lands on. The key is
// opaque to this package, never logged, held in locked memory, and wiped by Close
// (AN-8). Remote response bodies are redacted because a compromised gateway could echo
// it. The deterministic retry key is hashed only through internal/crypto (AN-3).
//
// A channel does exactly one thing — POST a trigger event to one endpoint — and makes no
// other outbound calls (the least-privilege pattern of the connector SDK, S5.5).
//
// Delivery is at-least-once (the outbox may retry, AN-6). Every trigger carries a
// deterministic dedup_key derived from the tenant-scoped alert, so a retry updates the
// same PagerDuty incident instead of opening a duplicate incident.
package pagerduty

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
// The routing key is opaque, never logged, held in locked memory, and wiped by Close
// (AN-8).
type Channel struct {
	routingKey             *secret.Buffer // Events API v2 integration routing key; locked + wiped (AN-8)
	endpoint               string         // enqueue URL
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
// routingKey. Credential bytes are copied into locked, non-dumpable memory and must be
// released with Close. The endpoint defaults to the public Events API v2 enqueue
// endpoint. The default delivery path accepts only public HTTPS endpoints and uses the
// shared SSRF-safe HTTP client.
func New(routingKey []byte, opts ...Option) (*Channel, error) {
	if err := validateRoutingKey(routingKey); err != nil {
		return nil, err
	}
	key, err := secret.NewFrom(routingKey)
	if err != nil {
		return nil, fmt.Errorf("pagerduty: protect routing key: %w", err)
	}
	c := &Channel{
		routingKey: key,
		endpoint:   defaultEndpoint,
		doer:       netsec.SafeClient(10 * time.Second),
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// Close wipes and releases the routing key. It is safe to call more than once.
func (c *Channel) Close() {
	if c != nil && c.routingKey != nil {
		c.routingKey.Destroy()
	}
}

// Name identifies the channel.
func (c *Channel) Name() string { return "pagerduty" }

// Notify triggers a PagerDuty incident for the alert. It POSTs an Events API v2 trigger
// event whose payload summary is notify.FormatMessage(alert). Only the vendor's exact
// 202 response acknowledging the submitted dedup key is success; remote response bodies
// are discarded (AN-8). The dedup key makes outbox retries address one incident (AN-6).
func (c *Channel) Notify(ctx context.Context, alert notify.Alert) error {
	if !c.skipEndpointValidation {
		if err := netsec.ValidatePublicHTTPSURL(c.endpoint); err != nil {
			return fmt.Errorf("pagerduty: validate endpoint: %w", err)
		}
	}
	if c.routingKey == nil || c.routingKey.Len() == 0 {
		return errors.New("pagerduty: routing key is unavailable")
	}
	dedupKey, err := alertDedupKey(alert)
	if err != nil {
		return fmt.Errorf("pagerduty: derive dedup key: %w", err)
	}
	payload, err := json.Marshal(eventRequest{
		EventAction: "trigger",
		DedupKey:    dedupKey,
		Payload: eventPayload{
			Summary:  notify.FormatMessage(alert),
			Source:   "trstctl",
			Severity: pagerDutySeverity(alert.Severity),
			CustomDetails: eventCustomDetails{
				Kind:          alert.Kind,
				TenantID:      alert.TenantID,
				CertificateID: alert.CertificateID,
				Detail:        alert.Detail,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("pagerduty: encode event: %w", err)
	}
	body := make([]byte, 0, len(payload)+c.routingKey.Len()+32)
	body = append(body, `{"routing_key":"`...)
	body = append(body, c.routingKey.Bytes()...)
	body = append(body, `",`...)
	// payload is an object. Splice its fields after the opening brace so the secret
	// never has to become an immutable Go string merely to satisfy encoding/json.
	body = append(body, payload[1:]...)
	defer secret.Wipe(body)

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
	if resp.StatusCode != http.StatusAccepted {
		return readError(resp)
	}
	responseBody, err := secret.ReadBounded(resp.Body, 1<<20)
	if err != nil {
		return errors.New("pagerduty: read accepted event response (details redacted)")
	}
	defer secret.Wipe(responseBody)
	var accepted struct {
		Status   json.RawMessage `json:"status"`
		DedupKey json.RawMessage `json:"dedup_key"`
	}
	defer func() {
		secret.Wipe(accepted.Status)
		secret.Wipe(accepted.DedupKey)
	}()
	if err := json.Unmarshal(responseBody, &accepted); err != nil {
		return errors.New("pagerduty: decode accepted event response (details redacted)")
	}
	expectedDedupKey := make([]byte, 0, len(dedupKey)+2)
	expectedDedupKey = append(expectedDedupKey, '"')
	expectedDedupKey = append(expectedDedupKey, dedupKey...)
	expectedDedupKey = append(expectedDedupKey, '"')
	defer secret.Wipe(expectedDedupKey)
	if !bytes.Equal(accepted.Status, []byte(`"success"`)) || !bytes.Equal(accepted.DedupKey, expectedDedupKey) {
		return errors.New("pagerduty: Events API did not acknowledge the submitted dedup key")
	}
	return nil
}

func validateRoutingKey(key []byte) error {
	if len(key) == 0 {
		return errors.New("pagerduty: routing key is required")
	}
	if len(key) > 255 {
		return errors.New("pagerduty: routing key is too long")
	}
	// PagerDuty integration keys are opaque ASCII tokens. Restricting the byte set
	// makes direct JSON framing safe without ever copying the secret into a string.
	for _, b := range key {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-' || b == '_' {
			continue
		}
		return errors.New("pagerduty: routing key contains a non-token byte")
	}
	return nil
}

func alertDedupKey(alert notify.Alert) (string, error) {
	encoded, err := json.Marshal(alert)
	if err != nil {
		return "", err
	}
	return "trstctl-" + crypto.SHA256Hex(encoded), nil
}

func pagerDutySeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case notify.AlertSeverityCritical:
		return "critical"
	case notify.AlertSeverityWarning:
		return "warning"
	default:
		return "info"
	}
}

// readError deliberately does not surface the remote body. A compromised gateway
// could echo the routing key; returning only the status keeps authority material out
// of logs while retaining the retryable failure signal.
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

var errRedacted = errors.New("request to pagerduty endpoint failed (details withheld to avoid leaking the endpoint URL)")

// eventRequest is the Events API v2 enqueue body. RoutingKey selects the target service;
// it is set here and nowhere else and is never written to logs or error text (AN-8).
type eventRequest struct {
	EventAction string       `json:"event_action"`
	DedupKey    string       `json:"dedup_key"`
	Payload     eventPayload `json:"payload"`
}

// eventPayload is the alert payload of an Events API v2 event.
type eventPayload struct {
	Summary       string             `json:"summary"`
	Source        string             `json:"source"`
	Severity      string             `json:"severity"`
	CustomDetails eventCustomDetails `json:"custom_details,omitempty"`
}

type eventCustomDetails struct {
	Kind          string `json:"kind,omitempty"`
	TenantID      string `json:"tenant_id,omitempty"`
	CertificateID string `json:"certificate_id,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

// apiError is a redacted non-2xx PagerDuty response.
type apiError struct {
	status int
}

func (e *apiError) Error() string {
	return fmt.Sprintf("pagerduty: status %d (response body redacted)", e.status)
}
