// SPDX-License-Identifier: MPL-2.0

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
	ChallengeHTTP01         = "http-01"
	ChallengeDNS01          = "dns-01"
	ChallengeTLSALPN01      = "tls-alpn-01"
	ChallengeDeviceAttest01 = "device-attest-01"
)

// Validator proves a client controls an identifier by completing a challenge.
// keyAuth is the expected key authorization (token "." accountKeyThumbprint).
//
// The production validator is Validators (dvmethod.go), which dispatches each of
// the three DV methods to a real per-type validator and fails closed on anything
// unknown. There is deliberately no accept-everything validator in the production
// build — the trivial always-accept one lives only in the test binary (see the
// internal acceptall_test.go), so no production-reachable path can skip
// validation.
type Validator interface {
	Validate(ctx context.Context, challengeType, domain, token, keyAuth string) error
}

// HTTP01Validator validates http-01 challenges by fetching the key authorization
// from the well-known URL on the identifier's domain (RFC 8555 §8.3).
//
// SSRF guard (SEC-006): the challenge domain is an attacker-influenced identifier,
// so the default client refuses to connect to a non-public resolved address
// (loopback, link-local incl. 169.254.169.254, private, unique-local) and bounds
// redirects, defeating a metadata/internal-endpoint fetch and DNS rebinding. An
// explicitly injected Client is trusted and used as-is (e.g. the conformance
// harness pointing at a loopback test server); AllowPrivateTargets opts the
// default client out of the guard for tests that must dial loopback directly.
type HTTP01Validator struct {
	Client *http.Client
	// AllowPrivateTargets disables the SSRF guard on the DEFAULT client only. It
	// exists for tests that deliberately dial a loopback httptest server; it is
	// false in production, where every fetch is guarded.
	AllowPrivateTargets bool
}

// Validate performs the http-01 check.
func (v HTTP01Validator) Validate(ctx context.Context, challengeType, domain, token, keyAuth string) error {
	if challengeType != ChallengeHTTP01 {
		return fmt.Errorf("acme: HTTP01Validator cannot validate %q", challengeType)
	}
	client := v.Client
	if client == nil {
		// Default to the SSRF-guarded client (SEC-006). Tests that must reach loopback
		// set AllowPrivateTargets to get an unguarded default instead.
		if v.AllowPrivateTargets {
			client = &http.Client{Timeout: 5 * time.Second}
		} else {
			client = ssrfSafeClient(5 * time.Second)
		}
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
