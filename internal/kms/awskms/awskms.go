// Package awskms is the AWS KMS key-management backend (S9.3), built from the S9.1
// backend template behind the AN-3 crypto boundary. GenerateKey creates an asymmetric
// KMS key (KeyUsage SIGN_VERIFY) and returns a crypto.Signer that signs via the KMS Sign
// API — the private key never leaves KMS. The keyed MAC and digests route through
// internal/crypto (no crypto/*); SigV4 is computed exactly as the ACM connector does.
//
// It speaks the AWS JSON 1.1 wire protocol directly over an injectable HTTP doer so it is
// exercised against a faithful in-process double on CI; real-backend validation is
// deferred (the same pattern Phase 1 used for the cloud connectors).
package awskms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/crypto"
)

const (
	service  = "kms"
	jsonType = "application/x-amz-json-1.1"
)

// Credentials are the AWS access credentials used to sign requests. SessionToken is set
// for temporary (STS/role) credentials. They are opaque here, never logged.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// HTTPDoer is the minimal HTTP client seam (tests inject the double's client).
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// defaultOpTimeout bounds a single KMS network operation when the caller does not
// supply its own deadline. It exists so an interface-forced context.Background()
// (a Sign/GenerateKey reached through the context-less crypto.Signer interface)
// cannot hang a worker goroutine forever on a wedged KMS endpoint, defeating AN-7
// backpressure for the slowest possible operation — a remote crypto call
// (CODE-002). A caller that threads its own deadline via the ContextSigner path
// overrides this entirely.
const defaultOpTimeout = 30 * time.Second

// Backend is an AWS KMS crypto.Backend.
type Backend struct {
	region    string
	endpoint  string
	host      string
	creds     Credentials
	doer      HTTPDoer
	now       func() time.Time
	opTimeout time.Duration
}

var (
	_ crypto.Backend             = (*Backend)(nil)
	_ crypto.ContextKeyGenerator = (*Backend)(nil)
	_ crypto.ContextSigner       = (*kmsSigner)(nil)
)

// Option configures a Backend.
type Option func(*Backend)

// WithEndpoint overrides the regional KMS endpoint (tests, VPC endpoints, partitions).
func WithEndpoint(endpoint string) Option { return func(b *Backend) { b.setEndpoint(endpoint) } }

// WithHTTPClient injects the HTTP doer (tests pass the double's client).
func WithHTTPClient(d HTTPDoer) Option { return func(b *Backend) { b.doer = d } }

// WithOpTimeout sets the per-operation timeout applied when a Sign/GenerateKey is
// reached through the context-less crypto.Signer/KeyGenerator interface (CODE-002).
// A non-positive value disables the floor (the call then blocks until the doer
// returns). It does not affect calls made through the ContextSigner path, where
// the caller's own deadline governs.
func WithOpTimeout(d time.Duration) Option { return func(b *Backend) { b.opTimeout = d } }

// New returns an AWS KMS backend for region, signing with creds.
func New(region string, creds Credentials, opts ...Option) *Backend {
	b := &Backend{region: region, creds: creds, doer: http.DefaultClient, now: time.Now, opTimeout: defaultOpTimeout}
	b.setEndpoint(fmt.Sprintf("https://kms.%s.amazonaws.com", region))
	for _, o := range opts {
		o(b)
	}
	return b
}

// opContext derives the context a single network operation runs under when the
// caller did not provide one. When the caller threads a real context (the
// ContextSigner path), that context already carries any deadline and is used
// as-is; this is only the fallback for the interface-forced background context.
func (b *Backend) opContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if b.opTimeout <= 0 {
		return ctx, func() {}
	}
	// Only impose the floor when the caller has not already set a deadline.
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, b.opTimeout)
}

func (b *Backend) setEndpoint(endpoint string) {
	b.endpoint = strings.TrimRight(endpoint, "/")
	if u, err := url.Parse(endpoint); err == nil {
		b.host = u.Host
	}
}

// Name identifies the backend.
func (b *Backend) Name() string { return "aws-kms" }

// GenerateKey creates an asymmetric signing key in KMS and returns a Signer for it.
// It is the context-less crypto.KeyGenerator entry point; it applies the backend's
// per-operation timeout floor so a wedged KMS cannot hang the caller (CODE-002).
// Callers holding a context should prefer GenerateKeyContext.
func (b *Backend) GenerateKey(alg crypto.Algorithm) (crypto.Signer, error) {
	return b.GenerateKeyContext(context.Background(), alg)
}

// GenerateKeyContext is the context-bearing key generation (crypto.ContextKeyGenerator):
// the caller's context bounds and can cancel every KMS round-trip the generation makes.
func (b *Backend) GenerateKeyContext(ctx context.Context, alg crypto.Algorithm) (crypto.Signer, error) {
	spec, err := keySpec(alg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	var created struct {
		KeyMetadata struct{ KeyId string }
	}
	if err := b.call(ctx, "TrentService.CreateKey",
		map[string]string{"KeySpec": spec, "KeyUsage": "SIGN_VERIFY"}, &created); err != nil {
		return nil, fmt.Errorf("aws-kms: create key: %w", err)
	}
	keyID := created.KeyMetadata.KeyId
	pub, err := b.publicKey(ctx, keyID, alg)
	if err != nil {
		return nil, err
	}
	return &kmsSigner{b: b, keyID: keyID, alg: alg, pub: pub}, nil
}

func (b *Backend) publicKey(ctx context.Context, keyID string, alg crypto.Algorithm) (crypto.PublicKey, error) {
	var out struct{ PublicKey string } // base64 DER SubjectPublicKeyInfo
	if err := b.call(ctx, "TrentService.GetPublicKey", map[string]string{"KeyId": keyID}, &out); err != nil {
		return crypto.PublicKey{}, fmt.Errorf("aws-kms: get public key: %w", err)
	}
	der, err := base64.StdEncoding.DecodeString(out.PublicKey)
	if err != nil {
		return crypto.PublicKey{}, fmt.Errorf("aws-kms: decode public key: %w", err)
	}
	return crypto.PublicKey{Algorithm: alg, DER: der}, nil
}

// kmsSigner signs a digest via the KMS Sign API; the key never leaves KMS.
type kmsSigner struct {
	b     *Backend
	keyID string
	alg   crypto.Algorithm
	pub   crypto.PublicKey
}

func (s *kmsSigner) Public() crypto.PublicKey    { return s.pub }
func (s *kmsSigner) Algorithm() crypto.Algorithm { return s.alg }

// Sign is the context-less crypto.Signer entry point; it applies the backend's
// per-operation timeout floor so a wedged KMS cannot hang the caller (CODE-002).
// Callers holding a context should prefer SignContext.
func (s *kmsSigner) Sign(message []byte, opts crypto.SignOptions) ([]byte, error) {
	return s.SignContext(context.Background(), message, opts)
}

// SignContext is the context-bearing signing operation (crypto.ContextSigner): the
// caller's context bounds and can cancel the remote KMS Sign call.
func (s *kmsSigner) SignContext(ctx context.Context, message []byte, opts crypto.SignOptions) ([]byte, error) {
	digest, err := crypto.Digest(hashOf(opts), message)
	if err != nil {
		return nil, err
	}
	sa, err := signingAlgorithm(s.alg, opts)
	if err != nil {
		return nil, err
	}
	ctx, cancel := s.b.opContext(ctx)
	defer cancel()
	var out struct{ Signature string }
	req := map[string]string{
		"KeyId":            s.keyID,
		"Message":          base64.StdEncoding.EncodeToString(digest),
		"MessageType":      "DIGEST",
		"SigningAlgorithm": sa,
	}
	if err := s.b.call(ctx, "TrentService.Sign", req, &out); err != nil {
		return nil, fmt.Errorf("aws-kms: sign: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(out.Signature)
	if err != nil {
		return nil, fmt.Errorf("aws-kms: decode signature: %w", err)
	}
	return sig, nil
}

// call performs a signed AWS JSON 1.1 request and decodes the JSON response.
//
// The provider-specific parts stay here: the AWS JSON 1.1 URL/headers, and SigV4 —
// supplied as a cloudhttp request-signer closure so the keyed MAC stays in this
// package behind the internal/crypto boundary (AN-3) while the bounded read, non-2xx
// normalisation, JSON decode, and timeout floor are the shared internal/cloudhttp
// round-trip (CODE-006). The per-op timeout is already applied by the caller via
// opContext(ctx) (CODE-002), so the context already carries the deadline and the
// shared floor is left off here.
func (b *Backend) call(ctx context.Context, target string, in any, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint+"/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", jsonType)
	req.Header.Set("X-Amz-Target", target)
	// Record the marshalled body so the SigV4 signer hashes exactly the bytes sent.
	req = cloudhttp.SetBody(req, body)
	if err := cloudhttp.JSON(b.doer, req, out, cloudhttp.WithSigner(b.sigV4Signer())); err != nil {
		return err
	}
	return nil
}

// sigV4Signer returns the cloudhttp request-signer that stamps SigV4 onto a request
// just before it is sent. The keyed MAC it computes routes through internal/crypto
// (AN-3); the signing key never leaves this package.
func (b *Backend) sigV4Signer() cloudhttp.Signer {
	return func(req *http.Request, body []byte) error {
		b.signV4(req, body, b.now().UTC())
		return nil
	}
}

// signV4 adds AWS Signature Version 4 headers (digests/MAC via the crypto boundary, AN-3;
// identical to the ACM connector with service="kms").
func (b *Backend) signV4(req *http.Request, body []byte, t time.Time) {
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	if b.creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", b.creds.SessionToken)
	}
	signed := []string{"content-type", "host", "x-amz-date", "x-amz-target"}
	if b.creds.SessionToken != "" {
		signed = append(signed, "x-amz-security-token")
	}
	sort.Strings(signed)
	var canonHeaders strings.Builder
	for _, h := range signed {
		v := strings.TrimSpace(req.Header.Get(h))
		if h == "host" {
			v = b.host
		}
		canonHeaders.WriteString(h + ":" + v + "\n")
	}
	signedHeaders := strings.Join(signed, ";")
	canonicalRequest := strings.Join([]string{
		req.Method, req.URL.EscapedPath(), "", canonHeaders.String(), signedHeaders, crypto.SHA256Hex(body),
	}, "\n")
	credScope := dateStamp + "/" + b.region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, credScope, crypto.SHA256Hex([]byte(canonicalRequest)),
	}, "\n")
	kDate := crypto.HMACSHA256([]byte("AWS4"+b.creds.SecretAccessKey), []byte(dateStamp))
	kRegion := crypto.HMACSHA256(kDate, []byte(b.region))
	kService := crypto.HMACSHA256(kRegion, []byte(service))
	kSigning := crypto.HMACSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(crypto.HMACSHA256(kSigning, []byte(stringToSign)))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 "+
		"Credential="+b.creds.AccessKeyID+"/"+credScope+", "+
		"SignedHeaders="+signedHeaders+", Signature="+signature)
}

func hashOf(opts crypto.SignOptions) crypto.Hash {
	if opts.Hash == "" {
		return crypto.SHA256
	}
	return opts.Hash
}

func keySpec(alg crypto.Algorithm) (string, error) {
	switch alg {
	case crypto.RSA2048:
		return "RSA_2048", nil
	case crypto.RSA3072:
		return "RSA_3072", nil
	case crypto.RSA4096:
		return "RSA_4096", nil
	case crypto.ECDSAP256:
		return "ECC_NIST_P256", nil
	case crypto.ECDSAP384:
		return "ECC_NIST_P384", nil
	case crypto.ECDSAP521:
		return "ECC_NIST_P521", nil
	default:
		return "", fmt.Errorf("aws-kms: unsupported algorithm %q", alg)
	}
}

func signingAlgorithm(alg crypto.Algorithm, opts crypto.SignOptions) (string, error) {
	suffix := map[crypto.Hash]string{crypto.SHA256: "SHA_256", crypto.SHA384: "SHA_384", crypto.SHA512: "SHA_512"}[hashOf(opts)]
	if suffix == "" {
		return "", fmt.Errorf("aws-kms: unsupported hash %q", opts.Hash)
	}
	switch alg {
	case crypto.RSA2048, crypto.RSA3072, crypto.RSA4096:
		if opts.RSAPadding == crypto.RSAPSS {
			return "RSASSA_PSS_" + suffix, nil
		}
		return "RSASSA_PKCS1_V1_5_" + suffix, nil
	case crypto.ECDSAP256, crypto.ECDSAP384, crypto.ECDSAP521:
		return "ECDSA_" + suffix, nil
	default:
		return "", fmt.Errorf("aws-kms: unsupported algorithm %q", alg)
	}
}
