// SPDX-License-Identifier: BUSL-1.1

package secretsync

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/secrettext"
)

// The signed webhook (A202). A delivery POSTs JSON to the operator's endpoint
// and signs it with the target's HMAC key, the same handshake as the
// notification webhook plus a signed timestamp:
//
//	X-Trstctl-Timestamp: <unix seconds>
//	X-Trstctl-Signature: sha256=<hex HMAC-SHA256(key, timestamp + "." + body)>
//	X-Trstctl-Delivery:  <delivery id, stable across retries>
//
// A receiver recomputes the MAC over the timestamp and the exact body bytes it
// received (VerifyWebhookSignature), so a changed body fails, and it refuses a
// timestamp outside its tolerance, so a captured delivery cannot be replayed
// later to roll a secret back.
const (
	WebhookTimestampHeader = "X-Trstctl-Timestamp"
	WebhookSignatureHeader = "X-Trstctl-Signature"
	WebhookDeliveryHeader  = "X-Trstctl-Delivery"
	// DefaultWebhookTolerance is how far a receiver lets a timestamp drift.
	DefaultWebhookTolerance = 5 * time.Minute
)

// DefaultWebhookTemplate is the body when the target configures none.
const DefaultWebhookTemplate = `{"key":"${key}","value_base64":"${value_base64}","delivery_id":"${delivery_id}","timestamp":${timestamp}}`

var errWebhookSignature = errors.New("secretsync: webhook signature does not verify")

// WebhookConfig configures the signed, templated webhook destination.
type WebhookConfig struct {
	Endpoint   string
	HTTPClient HTTPDoer
	// SigningKey is the HMAC key the receiver shares; required.
	SigningKey []byte
	// BearerToken optionally authenticates the request as well.
	BearerToken []byte
	// BodyTemplate is JSON with ${key}, ${value}, ${value_base64},
	// ${delivery_id} and ${timestamp} placeholders; empty is the default.
	BodyTemplate string
	Now          func() time.Time
}

// WebhookPusher delivers one signed, templated JSON body per secret.
type WebhookPusher struct {
	endpoint string
	doer     HTTPDoer
	key      *secret.Buffer
	token    *secret.Buffer
	template []webhookSegment
	now      func() time.Time
}

// webhookSegment is literal template text or one placeholder.
type webhookSegment struct {
	literal     string
	placeholder string
}

// ValidateWebhookTemplate parses a body template and proves it renders valid
// JSON carrying the secret; config validation and the pusher share it.
func ValidateWebhookTemplate(template string) error {
	segments, err := parseWebhookTemplate(template)
	if err != nil {
		return err
	}
	carries := false
	for _, s := range segments {
		carries = carries || s.placeholder == "value" || s.placeholder == "value_base64"
	}
	if !carries {
		return errors.New("secretsync: webhook template must carry ${value} or ${value_base64}")
	}
	sample, err := renderWebhookBody(segments, "sample/key", []byte("sample \"value\"\n"), "delivery-1", 1700000000)
	if err != nil {
		return err
	}
	defer secret.Wipe(sample)
	if !json.Valid(sample) {
		return errors.New("secretsync: webhook template does not render valid JSON (put string placeholders inside quotes)")
	}
	return nil
}

func parseWebhookTemplate(template string) ([]webhookSegment, error) {
	if strings.TrimSpace(template) == "" {
		template = DefaultWebhookTemplate
	}
	var segments []webhookSegment
	rest := template
	for {
		i := strings.Index(rest, "${")
		if i < 0 {
			if rest != "" {
				segments = append(segments, webhookSegment{literal: rest})
			}
			return segments, nil
		}
		if i > 0 {
			segments = append(segments, webhookSegment{literal: rest[:i]})
		}
		end := strings.IndexByte(rest[i:], '}')
		if end < 0 {
			return nil, errors.New("secretsync: webhook template has an unterminated ${")
		}
		name := rest[i+2 : i+end]
		switch name {
		case "key", "value", "value_base64", "delivery_id", "timestamp":
		default:
			return nil, fmt.Errorf("secretsync: webhook template placeholder ${%s} is not one of key, value, value_base64, delivery_id, timestamp", name)
		}
		segments = append(segments, webhookSegment{placeholder: name})
		rest = rest[i+end+1:]
	}
}

// renderWebhookBody fills the template into one buffer the caller wipes; the
// secret never becomes a Go string.
func renderWebhookBody(segments []webhookSegment, key string, value []byte, deliveryID string, timestamp int64) ([]byte, error) {
	body := make([]byte, 0, 256+2*len(value))
	for _, s := range segments {
		switch s.placeholder {
		case "":
			body = append(body, s.literal...)
		case "key":
			body = appendJSONStringContent(body, []byte(key))
		case "value":
			if !utf8.Valid(value) {
				secret.Wipe(body)
				return nil, errors.New("secretsync: ${value} needs a UTF-8 secret; use ${value_base64}")
			}
			body = appendJSONStringContent(body, value)
		case "value_base64":
			body = base64.StdEncoding.AppendEncode(body, value)
		case "delivery_id":
			body = appendJSONStringContent(body, []byte(deliveryID))
		case "timestamp":
			body = strconv.AppendInt(body, timestamp, 10)
		}
	}
	return body, nil
}

// NewWebhookPusher builds the signed webhook pusher; the template is validated.
func NewWebhookPusher(cfg WebhookConfig) (*WebhookPusher, error) {
	if strings.TrimSpace(cfg.Endpoint) == "" || len(cfg.SigningKey) == 0 {
		return nil, errors.New("secretsync: webhook endpoint and signing key are required")
	}
	if err := ValidateWebhookTemplate(cfg.BodyTemplate); err != nil {
		return nil, err
	}
	segments, err := parseWebhookTemplate(cfg.BodyTemplate)
	if err != nil {
		return nil, err
	}
	doer := cfg.HTTPClient
	if doer == nil {
		doer = netsec.HardenedClient(30 * time.Second)
	}
	key, err := lockOptionalSecret(cfg.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("secretsync: lock webhook signing key: %w", err)
	}
	token, err := lockOptionalSecret(cfg.BearerToken)
	if err != nil {
		destroySecretBuffer(&key)
		return nil, fmt.Errorf("secretsync: lock webhook bearer token: %w", err)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &WebhookPusher{endpoint: strings.TrimSpace(cfg.Endpoint), doer: doer, key: key, token: token, template: segments, now: now}, nil
}

// Push renders, signs and delivers one secret.
func (p *WebhookPusher) Push(ctx context.Context, key string, value []byte) error {
	timestamp := p.now().Unix()
	deliveryID := operationIDFromContext(ctx)
	body, err := renderWebhookBody(p.template, key, value, deliveryID, timestamp)
	if err != nil {
		return err
	}
	defer secret.Wipe(body)
	signature := WebhookSignature(secretBufferBytes(p.key), timestamp, body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(WebhookTimestampHeader, strconv.FormatInt(timestamp, 10))
	req.Header.Set(WebhookSignatureHeader, signature)
	if deliveryID != "" {
		req.Header.Set(WebhookDeliveryHeader, deliveryID)
	}
	if token := secretBufferBytes(p.token); len(token) > 0 {
		req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
	}
	return expect2xx(p.doer, req)
}

// Close destroys the retained key and token.
func (p *WebhookPusher) Close() {
	destroySecretBuffer(&p.key)
	destroySecretBuffer(&p.token)
}

// WebhookSignature is the X-Trstctl-Signature value for a timestamp and body:
// sha256=<hex HMAC-SHA256(key, timestamp + "." + body)>.
func WebhookSignature(key []byte, timestamp int64, body []byte) string {
	signed := make([]byte, 0, 24+len(body))
	signed = strconv.AppendInt(signed, timestamp, 10)
	signed = append(signed, '.')
	signed = append(signed, body...)
	mac := crypto.HMACSHA256(key, signed)
	secret.Wipe(signed)
	return "sha256=" + hex.EncodeToString(mac)
}

// VerifyWebhookSignature is the receiver's check: the timestamp header must be
// within tolerance of now (DefaultWebhookTolerance when zero), and the
// signature header must be the MAC of that timestamp and the exact body.
func VerifyWebhookSignature(key []byte, timestampHeader string, body []byte, signatureHeader string, now time.Time, tolerance time.Duration) error {
	if tolerance <= 0 {
		tolerance = DefaultWebhookTolerance
	}
	timestamp, err := strconv.ParseInt(strings.TrimSpace(timestampHeader), 10, 64)
	if err != nil || len(key) == 0 {
		return errWebhookSignature
	}
	if drift := now.Sub(time.Unix(timestamp, 0)); drift > tolerance || drift < -tolerance {
		return errWebhookSignature
	}
	want := WebhookSignature(key, timestamp, body)
	if !crypto.ConstantTimeEqual([]byte(strings.TrimSpace(signatureHeader)), []byte(want)) {
		return errWebhookSignature
	}
	return nil
}
