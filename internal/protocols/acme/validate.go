package acme

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Challenge types this server offers (RFC 8555 §8).
const (
	ChallengeHTTP01    = "http-01"
	ChallengeDNS01     = "dns-01"
	ChallengeTLSALPN01 = "tls-alpn-01"
)

// Validator proves a client controls an identifier by completing a challenge.
// keyAuth is the expected key authorization (token "." accountKeyThumbprint).
type Validator interface {
	Validate(ctx context.Context, challengeType, domain, token, keyAuth string) error
}

// AcceptAll is a Validator that accepts every challenge without checking. It is
// for tests and local development only — never for a real deployment.
type AcceptAll struct{}

// Validate always succeeds.
func (AcceptAll) Validate(context.Context, string, string, string, string) error { return nil }

// HTTP01Validator validates http-01 challenges by fetching the key authorization
// from the well-known URL on the identifier's domain (RFC 8555 §8.3).
type HTTP01Validator struct {
	Client *http.Client
}

// Validate performs the http-01 check.
func (v HTTP01Validator) Validate(ctx context.Context, challengeType, domain, token, keyAuth string) error {
	if challengeType != ChallengeHTTP01 {
		return fmt.Errorf("acme: HTTP01Validator cannot validate %q", challengeType)
	}
	client := v.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	url := "http://" + domain + "/.well-known/acme-challenge/" + token
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("acme: http-01 fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("acme: http-01 returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(body)) != keyAuth {
		return fmt.Errorf("acme: http-01 key authorization mismatch")
	}
	return nil
}
