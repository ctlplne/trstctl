// Package trstctl is the official Go client SDK for the trstctl control-plane
// REST API. It is generated/blessed against the SERVED OpenAPI 3.1 contract
// (clients/sdk/openapi.json, which is pinned byte-for-byte to the live spec by
// the Go test internal/api.TestSDKSpecPinnedToGolden), so the request/response
// shapes here cannot silently drift from the API.
//
// What the SDK gives an integrator out of the box (so every language team does
// not re-implement them):
//
//   - Auth: an Authorization: Bearer <token> header is injected on every call
//     (Client.Token); an optional X-Tenant-ID hint can be set for header/dev
//     auth (Client.Tenant).
//   - Idempotency (AN-5): every mutation (POST/PUT/DELETE) carries an
//     Idempotency-Key. If the caller does not supply one, a fresh key is
//     generated, so a transparently retried mutation cannot execute twice.
//   - problem+json errors (RFC 7807): any non-2xx response with an
//     application/problem+json body is parsed into a typed *Problem (also an
//     error), exposing Status/Title/Detail/Type/Instance and extension members.
//   - Retries with backoff: idempotent failures (429/502/503/504) are retried
//     with exponential backoff, honoring a Retry-After header when present.
//   - Cursor pagination: List* methods return an (items, next_cursor) page, and
//     a generic Iterator follows next_cursor so callers can range over every
//     item without juggling cursors by hand.
//
// The zero dependencies (standard library only) keep the SDK's supply chain
// minimal — appropriate for a client that handles credential lifecycle.
package trstctl

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultUserAgent identifies the SDK in the User-Agent header so operators can
// see which client made a call in server logs.
const DefaultUserAgent = "trstctl-go-sdk/1"

// Client talks to a trstctl control plane. The zero value is not usable; build
// one with New. A Client is safe for concurrent use by multiple goroutines once
// constructed (it holds no per-call mutable state).
type Client struct {
	// BaseURL is the control-plane base URL, e.g. "https://localhost:8443".
	// A trailing slash is tolerated. Resource paths are appended to it.
	BaseURL string

	// Token is the trstctl API token, sent as "Authorization: Bearer <token>".
	// A trstctl token carries its own tenant and scopes, so Tenant is usually
	// unnecessary when Token is set.
	Token string

	// Tenant, when non-empty, is sent as the X-Tenant-ID header. It is only a
	// lookup hint for header/dev auth and machine-login flows; an authenticated
	// Bearer token is authoritative for the tenant.
	Tenant string

	// HTTPClient performs the requests. If nil, a client with a 30s timeout is
	// used. Provide your own to control TLS (e.g. a custom CA bundle), proxies,
	// or timeouts.
	HTTPClient *http.Client

	// UserAgent overrides DefaultUserAgent when set.
	UserAgent string

	// Retry controls automatic retries of idempotent failures. The zero value
	// (DefaultRetry) retries 429/502/503/504 a few times with backoff.
	Retry RetryPolicy
}

// RetryPolicy configures automatic retries. Retries apply to requests the SDK
// can safely repeat: GETs, and mutations (which always carry a stable
// Idempotency-Key, so a repeat is exactly-once on the server, AN-5).
type RetryPolicy struct {
	// MaxAttempts is the total number of attempts (1 = no retry). Values < 1
	// fall back to DefaultRetry.MaxAttempts.
	MaxAttempts int
	// BaseDelay is the first backoff delay; it doubles each attempt up to
	// MaxDelay. A server Retry-After header overrides the computed delay.
	BaseDelay time.Duration
	// MaxDelay caps the per-attempt backoff.
	MaxDelay time.Duration
}

// DefaultRetry is the retry policy used when Client.Retry is the zero value.
var DefaultRetry = RetryPolicy{MaxAttempts: 4, BaseDelay: 200 * time.Millisecond, MaxDelay: 5 * time.Second}

func (r RetryPolicy) withDefaults() RetryPolicy {
	if r.MaxAttempts < 1 {
		r.MaxAttempts = DefaultRetry.MaxAttempts
	}
	if r.BaseDelay <= 0 {
		r.BaseDelay = DefaultRetry.BaseDelay
	}
	if r.MaxDelay <= 0 {
		r.MaxDelay = DefaultRetry.MaxDelay
	}
	return r
}

// New constructs a Client for baseURL with the given API token. Pass functional
// options to set a tenant hint, a custom *http.Client, or a retry policy.
func New(baseURL, token string, opts ...Option) *Client {
	c := &Client{BaseURL: baseURL, Token: token}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Option configures a Client built with New.
type Option func(*Client)

// WithTenant sets the X-Tenant-ID hint header.
func WithTenant(tenant string) Option { return func(c *Client) { c.Tenant = tenant } }

// WithHTTPClient sets the underlying *http.Client (for custom TLS, proxy, or
// timeout configuration).
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.HTTPClient = h } }

// WithUserAgent overrides the User-Agent header.
func WithUserAgent(ua string) Option { return func(c *Client) { c.UserAgent = ua } }

// WithRetry sets the retry policy.
func WithRetry(p RetryPolicy) Option { return func(c *Client) { c.Retry = p } }

// Problem is an RFC 7807 problem+json error returned by the API on a non-2xx
// response. It implements error, so callers can both `errors.As` it for the
// structured fields and treat it as a plain error. Standard members are typed;
// any extension members (e.g. a rate-limit hint) are kept in Extensions.
type Problem struct {
	Type       string         `json:"type,omitempty"`
	Title      string         `json:"title,omitempty"`
	Status     int            `json:"status,omitempty"`
	Detail     string         `json:"detail,omitempty"`
	Instance   string         `json:"instance,omitempty"`
	Extensions map[string]any `json:"-"`

	// HTTPStatus is the actual HTTP status code of the response, which is
	// authoritative even if the body omits or mismatches the "status" member.
	HTTPStatus int `json:"-"`
	// RetryAfter is the parsed Retry-After header (seconds), if the server sent
	// one (typically on 429). Zero means absent/unparseable.
	RetryAfter time.Duration `json:"-"`
}

// Error implements error.
func (p *Problem) Error() string {
	status := p.HTTPStatus
	if status == 0 {
		status = p.Status
	}
	title := p.Title
	if title == "" {
		title = http.StatusText(status)
	}
	if p.Detail != "" {
		return fmt.Sprintf("trstctl: %d %s: %s", status, title, p.Detail)
	}
	return fmt.Sprintf("trstctl: %d %s", status, title)
}

// IsRateLimited reports whether this problem is a 429 Too Many Requests.
func (p *Problem) IsRateLimited() bool { return p.HTTPStatus == http.StatusTooManyRequests }

// UnmarshalJSON parses an RFC 7807 object, routing unknown members into
// Extensions so a value round-trips (matching internal/api/problem).
func (p *Problem) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*p = Problem{}
	getString(raw, "type", &p.Type)
	getString(raw, "title", &p.Title)
	if v, ok := raw["status"]; ok {
		_ = json.Unmarshal(v, &p.Status)
		delete(raw, "status")
	}
	getString(raw, "detail", &p.Detail)
	getString(raw, "instance", &p.Instance)
	if len(raw) > 0 {
		p.Extensions = make(map[string]any, len(raw))
		for k, v := range raw {
			var val any
			if err := json.Unmarshal(v, &val); err != nil {
				return err
			}
			p.Extensions[k] = val
		}
	}
	return nil
}

func getString(raw map[string]json.RawMessage, key string, dst *string) {
	if v, ok := raw[key]; ok {
		_ = json.Unmarshal(v, dst)
		delete(raw, key)
	}
}

// AsProblem extracts a *Problem from an error returned by the SDK, or nil/false
// if the error is not an API problem (e.g. a transport error). Convenience over
// errors.As for the common case.
func AsProblem(err error) (*Problem, bool) {
	var p *Problem
	if errors.As(err, &p) {
		return p, true
	}
	return nil, false
}

// httpClient returns the configured client or a sane default.
func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *Client) userAgent() string {
	if c.UserAgent != "" {
		return c.UserAgent
	}
	return DefaultUserAgent
}

// NewIdempotencyKey returns a fresh random Idempotency-Key. It is exported so
// callers can mint a key once and reuse it across their own retries of a single
// logical operation if they bypass the SDK's automatic retry.
func NewIdempotencyKey() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read essentially never fails; fall back to a time-based key so
		// the call still proceeds rather than panicking a credential operation.
		return "idem-" + strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return "idem-" + hex.EncodeToString(b[:])
}

// requestOptions carry per-call knobs internal to the SDK.
type requestOptions struct {
	query          url.Values
	body           any
	idempotencyKey string // explicit key; empty means auto-generate for mutations
}

// isMutation reports whether method changes server state (and so needs an
// Idempotency-Key per AN-5).
func isMutation(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// do executes a request with auth, idempotency, problem+json decoding, and
// retry/backoff, then decodes a 2xx JSON body into out (out may be nil for 204
// or when the caller ignores the body).
func (c *Client) do(ctx context.Context, method, path string, opts requestOptions, out any) error {
	if c.BaseURL == "" {
		return errors.New("trstctl: Client.BaseURL is empty")
	}
	u := strings.TrimRight(c.BaseURL, "/") + path
	if len(opts.query) > 0 {
		u += "?" + opts.query.Encode()
	}

	var rawBody []byte
	if opts.body != nil {
		b, err := json.Marshal(opts.body)
		if err != nil {
			return fmt.Errorf("trstctl: marshal request body: %w", err)
		}
		rawBody = b
	}

	// A mutation gets a stable Idempotency-Key for the WHOLE operation (held
	// constant across retries) so a retried POST is exactly-once on the server.
	idemKey := opts.idempotencyKey
	if idemKey == "" && isMutation(method) {
		idemKey = NewIdempotencyKey()
	}

	policy := c.Retry.withDefaults()
	var lastErr error
	for attempt := 1; attempt <= policy.MaxAttempts; attempt++ {
		var bodyReader io.Reader
		if rawBody != nil {
			bodyReader = bytes.NewReader(rawBody)
		}
		req, err := http.NewRequestWithContext(ctx, method, u, bodyReader)
		if err != nil {
			return fmt.Errorf("trstctl: build request: %w", err)
		}
		req.Header.Set("Accept", "application/json, application/problem+json")
		req.Header.Set("User-Agent", c.userAgent())
		if c.Token != "" {
			req.Header.Set("Authorization", "Bearer "+c.Token)
		}
		if c.Tenant != "" {
			req.Header.Set("X-Tenant-ID", c.Tenant)
		}
		if rawBody != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if idemKey != "" {
			req.Header.Set("Idempotency-Key", idemKey)
		}

		resp, err := c.httpClient().Do(req)
		if err != nil {
			// Transport error: retry if attempts remain and ctx is alive.
			lastErr = fmt.Errorf("trstctl: %s %s: %w", method, path, err)
			if attempt < policy.MaxAttempts && ctx.Err() == nil {
				if waitErr := sleepCtx(ctx, backoff(policy, attempt, 0)); waitErr != nil {
					return waitErr
				}
				continue
			}
			return lastErr
		}

		status := resp.StatusCode
		if status >= 200 && status < 300 {
			defer resp.Body.Close()
			if out == nil || status == http.StatusNoContent {
				_, _ = io.Copy(io.Discard, resp.Body)
				return nil
			}
			dec := json.NewDecoder(resp.Body)
			if err := dec.Decode(out); err != nil && !errors.Is(err, io.EOF) {
				return fmt.Errorf("trstctl: decode %s %s response: %w", method, path, err)
			}
			return nil
		}

		// Non-2xx: build a typed Problem from the (problem+json) body.
		prob := decodeProblem(resp)
		resp.Body.Close()
		lastErr = prob

		if isRetryableStatus(status) && attempt < policy.MaxAttempts && ctx.Err() == nil {
			delay := backoff(policy, attempt, prob.RetryAfter)
			if waitErr := sleepCtx(ctx, delay); waitErr != nil {
				return waitErr
			}
			continue
		}
		return lastErr
	}
	return lastErr
}

// decodeProblem reads a non-2xx response into a *Problem, always returning a
// non-nil value so callers get a usable error even if the body is empty or not
// problem+json.
func decodeProblem(resp *http.Response) *Problem {
	p := &Problem{HTTPStatus: resp.StatusCode}
	p.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if len(bytes.TrimSpace(body)) > 0 {
		// Tolerate either application/problem+json or a plain JSON object.
		_ = json.Unmarshal(body, p)
		// Re-assert the authoritative transport status/Retry-After, which
		// Unmarshal reset on the fresh struct it parsed into.
		p.HTTPStatus = resp.StatusCode
		p.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
		if p.Title == "" && p.Detail == "" && p.Type == "" {
			// Body was not problem-shaped; keep it as the detail so the error
			// is not empty.
			p.Detail = strings.TrimSpace(string(body))
		}
	}
	if p.Title == "" {
		p.Title = http.StatusText(resp.StatusCode)
	}
	return p
}

// isRetryableStatus reports whether an HTTP status warrants an automatic retry.
// 429 (rate limited) and 502/503/504 (transient upstream/availability) are the
// safe-to-retry statuses; 4xx client errors (other than 429) are not.
func isRetryableStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, // 429
		http.StatusBadGateway,         // 502
		http.StatusServiceUnavailable, // 503
		http.StatusGatewayTimeout:     // 504
		return true
	default:
		return false
	}
}

// backoff computes the delay before the next attempt: a server-provided
// Retry-After wins; otherwise exponential backoff (BaseDelay * 2^(attempt-1))
// capped at MaxDelay.
func backoff(p RetryPolicy, attempt int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		if retryAfter > p.MaxDelay {
			return p.MaxDelay
		}
		return retryAfter
	}
	d := p.BaseDelay
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= p.MaxDelay {
			return p.MaxDelay
		}
	}
	return d
}

// sleepCtx waits for d or until ctx is done, returning ctx.Err() if cancelled.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// parseRetryAfter reads a Retry-After header (RFC 7231: delta-seconds or an
// HTTP-date) into a duration, or 0 when absent/unparseable.
func parseRetryAfter(h string) time.Duration {
	if h == "" {
		return 0
	}
	if secs, err := strconv.Atoi(strings.TrimSpace(h)); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if when, err := http.ParseTime(h); err == nil {
		d := time.Until(when)
		if d < 0 {
			return 0
		}
		return d
	}
	return 0
}
