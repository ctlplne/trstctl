// Package cloudhttp is the thin shared HTTP round-trip used by trstctl's cloud
// provider families (KMS backends, DNS-01 providers) so the common request/response
// plumbing — bounded reads, non-2xx error normalisation, JSON decode, a per-call
// timeout floor, and a request-signing seam — lives in one place instead of being
// copy-pasted into each provider's package-local call()/do() (CODE-006).
//
// It deliberately does NOT own auth or URL construction: each provider still builds
// its own *http.Request (endpoint, path, query, and the credential — a bearer token,
// an API-key header, an AWS SigV4 signature, or Akamai EdgeGrid — which is
// provider-specific and must stay local so it is never logged, AN-8). cloudhttp owns
// only the parts that were genuinely identical across providers:
//
//   - apply a per-call timeout floor when the caller's context has no deadline,
//   - hand the request to a per-call Signer (the SigV4/EdgeGrid seam) just before it
//     is sent, so a signing provider shares this core without exporting its keys,
//   - send the request through an injectable Doer (so tests pass a double),
//   - read the body under a fixed cap so a hostile/huge response cannot exhaust
//     memory,
//   - turn a non-2xx status into a normalised *StatusError carrying the status and a
//     bounded, credential-free snippet of the body,
//   - decode a 2xx JSON body into out (when out != nil) or drain-and-discard it.
//
// No cryptographic operation happens here, so it imports no crypto/* (AN-3): a
// signing provider passes a Signer closure that computes its keyed MAC through the
// internal/crypto boundary and only mutates request headers — the key never crosses
// into this package.
//
// Adoption (CODE-006): every cloud provider family now routes its JSON/REST
// round-trip through cloudhttp.JSON —
//   - the bearer/API-key KMS backends internal/kms/gcpkms and internal/kms/azurekv;
//   - internal/kms/awskms, which passes a SigV4 Signer (its keyed MAC stays in the
//     awskms package, behind the crypto boundary) so AWS keeps its request signing
//     while sharing the bounded-read / timeout-floor / error-normalisation core;
//   - the eight internal/dns/* DNS-01 providers (cloudflare, ns1, azuredns, googledns,
//     ultradns, acmedns over their bearer/API-key headers; aws-route53 over a SigV4
//     Signer; akamai over an EdgeGrid Signer). The signing DNS providers carry their
//     keyed MAC through internal/crypto exactly as before; only the transport core is
//     shared. A single change to the timeout floor, the body bound, or the non-2xx
//     normalisation here is now inherited by every provider at once.
package cloudhttp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Doer is the minimal HTTP client seam: production passes http.DefaultClient (or a
// backend's configured client); tests pass a double. It matches the *HTTPDoer*
// interface each provider already defines, so a provider's existing doer satisfies
// it without change.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Signer is the per-request signing seam (AWS SigV4, Akamai EdgeGrid). It is called
// with the request and its already-marshalled body just before the request is sent,
// after the timeout floor has been applied, and is expected only to set
// authentication headers on req. The body bytes are passed separately because a
// signature is computed over a digest of the body and req.Body is a single-use
// stream the round-trip still needs to send. A Signer that returns an error aborts
// the call before any network I/O. The keyed MAC a Signer computes routes through
// internal/crypto in the provider package, so cloudhttp itself imports no crypto/*
// (AN-3); the signing key never enters this package.
type Signer func(req *http.Request, body []byte) error

const (
	// MaxBodyBytes caps a successful (decoded or drained) response body. 1 MiB is
	// ample for a KMS sign result or a DNS record list and bounds memory against a
	// hostile peer.
	MaxBodyBytes = 1 << 20
	// MaxErrorBytes caps the snippet of a non-2xx body included in the error.
	MaxErrorBytes = 4096
)

// StatusError is a normalised non-2xx response. Body is the (bounded, trimmed)
// response text; provider error bodies carry an API message and never echo the
// request's bearer token / key / signature, so surfacing them does not leak
// credentials (AN-8). Callers may wrap it with provider context (e.g.
// "azure-key-vault: sign: %w") or translate it into their own typed error
// (the DNS providers map it to a package-local *apiError that still exposes the
// status code their idempotency predicates inspect).
type StatusError struct {
	StatusCode int
	Body       string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("status %d: %s", e.StatusCode, e.Body)
}

// options is the resolved configuration of a single round-trip.
type options struct {
	timeout time.Duration
	sign    Signer
}

// Option configures a single cloudhttp call.
type Option func(*options)

// WithTimeout sets the per-call timeout floor: if d > 0 AND the request's context has
// no deadline of its own, the call is bounded by d so an interface-forced
// context.Background() cannot hang a worker on a wedged endpoint (the CODE-002
// timeout floor, shared here per CODE-006). A caller that already threads a deadline
// is left untouched. d <= 0 disables the floor.
func WithTimeout(d time.Duration) Option { return func(o *options) { o.timeout = d } }

// WithSigner installs the per-request Signer (SigV4/EdgeGrid). Without it, the request
// is sent exactly as the caller built it (the bearer/API-key providers, which set
// their credential header before calling JSON).
func WithSigner(s Signer) Option { return func(o *options) { o.sign = s } }

// JSON sends req through doer and decodes a 2xx JSON response into out (out may be nil
// to drain and discard the body). A non-2xx response yields a *StatusError with a
// bounded body snippet. Options configure the timeout floor (WithTimeout) and the
// request-signing seam (WithSigner); with no options it behaves as a plain bounded,
// error-normalising JSON round-trip.
func JSON(doer Doer, req *http.Request, out any, opts ...Option) error {
	var cfg options
	for _, o := range opts {
		o(&cfg)
	}

	if cfg.timeout > 0 {
		if _, hasDeadline := req.Context().Deadline(); !hasDeadline {
			ctx, cancel := context.WithTimeout(req.Context(), cfg.timeout)
			defer cancel()
			req = req.WithContext(ctx)
		}
	}

	if cfg.sign != nil {
		// The signer reads the body bytes the caller stashed for it; req.Body itself
		// remains the unconsumed stream the doer will send.
		if err := cfg.sign(req, signedBody(req)); err != nil {
			return err
		}
	}

	resp, err := doer.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBytes))
		return &StatusError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(msg))}
	}
	if out == nil {
		// Drain a bounded remainder so the connection can be reused, matching the
		// per-provider drain() the providers previously did by hand.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxBodyBytes))
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, MaxBodyBytes)).Decode(out)
}

// signedBody returns the body bytes a Signer must hash. A provider that signs a
// request stashes the marshalled body on the request via SetBody (below) so the
// signature is computed over the exact bytes that will be sent; if none was stashed
// (an empty-body request such as a GET/DELETE), the body is empty.
func signedBody(req *http.Request) []byte {
	if b, ok := req.Context().Value(bodyKey{}).([]byte); ok {
		return b
	}
	return nil
}

type bodyKey struct{}

// SetBody records the marshalled request body on req's context so a WithSigner Signer
// can hash exactly the bytes that will be transmitted, then returns the updated
// request. A signing provider builds its *http.Request with this body as the stream
// and calls SetBody with the same bytes; a nil/empty body (GET/DELETE) needs no call.
// This keeps the body available to the signer without re-reading the single-use
// req.Body stream.
func SetBody(req *http.Request, body []byte) *http.Request {
	if body == nil {
		return req
	}
	return req.WithContext(context.WithValue(req.Context(), bodyKey{}, body))
}
