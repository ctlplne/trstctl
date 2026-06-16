// Package gcpkms is the Google Cloud KMS key-management backend (S9.5), built from the
// S9.1 backend template behind the AN-3 crypto boundary. GenerateKey creates an
// ASYMMETRIC_SIGN crypto key (and its first key version) and returns a crypto.Signer that
// signs via the Cloud KMS asymmetricSign API — the private key never leaves KMS. Digests
// route through internal/crypto (no crypto/*); the only standard-library decoding used
// here is encoding/pem, which unwraps the PEM SubjectPublicKeyInfo Cloud KMS returns into
// the DER that crypto.PublicKey carries (encoding/pem is not part of crypto/*).
//
// Auth is OAuth2 Bearer: the caller supplies an access token (from a service account or
// workload identity, minted outside this package) and every request carries it as an
// Authorization: Bearer header. The token is opaque here and is never logged.
//
// It speaks the Cloud KMS REST/JSON wire protocol directly over an injectable HTTP doer so
// it is exercised against a faithful in-process double on CI; real-backend validation is
// deferred (the same pattern Phase 1 used for the cloud connectors).
package gcpkms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/crypto"
)

const defaultEndpoint = "https://cloudkms.googleapis.com/v1"

// defaultOpTimeout bounds a single Cloud KMS network operation when the caller
// does not supply its own deadline, so an interface-forced context.Background()
// cannot hang a worker on a wedged endpoint (CODE-002).
const defaultOpTimeout = 30 * time.Second

// Credentials are the OAuth2 access credentials used to authenticate to Cloud KMS. The
// BearerToken is a short-lived access token minted by the caller (service account or
// workload identity); it is opaque here and never logged.
type Credentials struct {
	BearerToken string
}

// HTTPDoer is the minimal HTTP client seam (tests inject the double's client).
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Backend is a Google Cloud KMS crypto.Backend. parent is the key ring under which keys
// are created, e.g. "projects/P/locations/L/keyRings/R".
type Backend struct {
	parent    string
	endpoint  string
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

// WithEndpoint overrides the Cloud KMS endpoint (tests, private service endpoints).
func WithEndpoint(endpoint string) Option {
	return func(b *Backend) { b.endpoint = strings.TrimRight(endpoint, "/") }
}

// WithHTTPClient injects the HTTP doer (tests pass the double's client).
func WithHTTPClient(d HTTPDoer) Option { return func(b *Backend) { b.doer = d } }

// WithOpTimeout sets the per-operation timeout applied when a Sign/GenerateKey is
// reached through the context-less crypto interface (CODE-002). A non-positive
// value disables the floor; it does not affect calls made through the
// ContextSigner path, where the caller's deadline governs.
func WithOpTimeout(d time.Duration) Option { return func(b *Backend) { b.opTimeout = d } }

// New returns a Cloud KMS backend that creates keys under parent (a key-ring resource name
// like "projects/P/locations/L/keyRings/R"), authenticating with creds.
func New(parent string, creds Credentials, opts ...Option) *Backend {
	b := &Backend{
		parent:    strings.Trim(parent, "/"),
		endpoint:  defaultEndpoint,
		creds:     creds,
		doer:      http.DefaultClient,
		now:       time.Now,
		opTimeout: defaultOpTimeout,
	}
	for _, o := range opts {
		o(b)
	}
	return b
}

// opContext derives the context a single network operation runs under when the
// caller did not provide a deadline (the interface-forced background path); a
// caller-supplied deadline (the ContextSigner path) is left untouched.
func (b *Backend) opContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if b.opTimeout <= 0 {
		return ctx, func() {}
	}
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, b.opTimeout)
}

// Name identifies the backend.
func (b *Backend) Name() string { return "gcp-kms" }

// GenerateKey creates an ASYMMETRIC_SIGN crypto key (with its first key version) and
// returns a Signer over that key version. The first version is created automatically and
// is reached at "{cryptoKey}/cryptoKeyVersions/1".
// GenerateKey is the context-less entry point; it applies the backend's
// per-operation timeout floor so a wedged KMS cannot hang the caller (CODE-002).
// Callers holding a context should prefer GenerateKeyContext.
func (b *Backend) GenerateKey(alg crypto.Algorithm) (crypto.Signer, error) {
	return b.GenerateKeyContext(context.Background(), alg)
}

// GenerateKeyContext is the context-bearing key generation (crypto.ContextKeyGenerator):
// the caller's context bounds and can cancel every KMS round-trip the generation makes.
func (b *Backend) GenerateKeyContext(ctx context.Context, alg crypto.Algorithm) (crypto.Signer, error) {
	gcpAlg, err := versionAlgorithm(alg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	keyID, err := newKeyID(b.now())
	if err != nil {
		return nil, fmt.Errorf("gcp-kms: generate key id: %w", err)
	}
	create := map[string]any{
		"purpose":         "ASYMMETRIC_SIGN",
		"versionTemplate": map[string]string{"algorithm": gcpAlg},
	}
	var created struct {
		Name string `json:"name"` // cryptoKey resource name
	}
	path := b.parent + "/cryptoKeys?cryptoKeyId=" + keyID
	if err := b.call(ctx, http.MethodPost, path, create, &created); err != nil {
		return nil, fmt.Errorf("gcp-kms: create key: %w", err)
	}
	cryptoKey := created.Name
	if cryptoKey == "" {
		cryptoKey = b.parent + "/cryptoKeys/" + keyID
	}
	versionName := cryptoKey + "/cryptoKeyVersions/1"
	pub, err := b.publicKey(ctx, versionName, alg)
	if err != nil {
		return nil, err
	}
	return &kmsSigner{b: b, versionName: versionName, alg: alg, pub: pub}, nil
}

// publicKey fetches the key version's public key (PEM SubjectPublicKeyInfo) and decodes
// the PEM wrapper to the DER that crypto.PublicKey carries.
func (b *Backend) publicKey(ctx context.Context, versionName string, alg crypto.Algorithm) (crypto.PublicKey, error) {
	var out struct {
		PEM string `json:"pem"` // PEM-encoded SubjectPublicKeyInfo
	}
	if err := b.call(ctx, http.MethodGet, versionName+"/publicKey", nil, &out); err != nil {
		return crypto.PublicKey{}, fmt.Errorf("gcp-kms: get public key: %w", err)
	}
	block, _ := pem.Decode([]byte(out.PEM))
	if block == nil {
		return crypto.PublicKey{}, fmt.Errorf("gcp-kms: public key is not valid PEM")
	}
	return crypto.PublicKey{Algorithm: alg, DER: block.Bytes}, nil
}

// kmsSigner signs a digest via the Cloud KMS asymmetricSign API; the key never leaves KMS.
type kmsSigner struct {
	b           *Backend
	versionName string
	alg         crypto.Algorithm
	pub         crypto.PublicKey
}

func (s *kmsSigner) Public() crypto.PublicKey    { return s.pub }
func (s *kmsSigner) Algorithm() crypto.Algorithm { return s.alg }

// Sign hashes message per opts and signs the digest with the remote key version. Cloud KMS
// carries the digest in a field named for its hash (sha256/sha384/sha512); the chosen field
// must match the key version's bound algorithm.
// Sign is the context-less entry point; it applies the backend's per-operation
// timeout floor so a wedged KMS cannot hang the caller (CODE-002). Callers holding
// a context should prefer SignContext.
func (s *kmsSigner) Sign(message []byte, opts crypto.SignOptions) ([]byte, error) {
	return s.SignContext(context.Background(), message, opts)
}

// SignContext is the context-bearing signing operation (crypto.ContextSigner): the
// caller's context bounds and can cancel the remote asymmetricSign call.
func (s *kmsSigner) SignContext(ctx context.Context, message []byte, opts crypto.SignOptions) ([]byte, error) {
	h := hashOf(opts)
	digest, err := crypto.Digest(h, message)
	if err != nil {
		return nil, err
	}
	field, err := digestField(h)
	if err != nil {
		return nil, err
	}
	ctx, cancel := s.b.opContext(ctx)
	defer cancel()
	req := map[string]any{
		"digest": map[string]string{field: base64.StdEncoding.EncodeToString(digest)},
	}
	var out struct {
		Signature string `json:"signature"` // base64-encoded signature
	}
	if err := s.b.call(ctx, http.MethodPost, s.versionName+":asymmetricSign", req, &out); err != nil {
		return nil, fmt.Errorf("gcp-kms: sign: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(out.Signature)
	if err != nil {
		return nil, fmt.Errorf("gcp-kms: decode signature: %w", err)
	}
	return sig, nil
}

// call performs an authenticated Cloud KMS JSON request and decodes the JSON response. A
// nil in sends no body. The provider-specific parts (URL, the Bearer auth header) stay
// here; the shared round-trip — bounded read, non-2xx normalisation, JSON decode — is
// internal/cloudhttp (CODE-006). The per-op timeout is already applied by the caller via
// withTimeout(ctx) (CODE-002), so the context carries the deadline and we pass 0 here.
func (b *Backend) call(ctx context.Context, method, path string, in any, out any) error {
	var body io.Reader
	if in != nil {
		buf, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(buf)
	}
	url := b.endpoint + "/" + strings.TrimLeft(path, "/")
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+b.creds.BearerToken)
	if err := cloudhttp.JSON(b.doer, req, out); err != nil {
		return fmt.Errorf("gcp-kms: %w", err)
	}
	return nil
}

// newKeyID derives a Cloud KMS-acceptable crypto-key id (letters, digits, hyphens,
// underscores; <=63 chars). It mixes the clock with random bytes so concurrent generations
// do not collide.
func newKeyID(t time.Time) (string, error) {
	rnd, err := crypto.RandomBytes(8)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("trstctl-%d-%x", t.UTC().Unix(), rnd), nil
}

func hashOf(opts crypto.SignOptions) crypto.Hash {
	if opts.Hash == "" {
		return crypto.SHA256
	}
	return opts.Hash
}

// digestField is the Cloud KMS Digest oneof field name for a hash.
func digestField(h crypto.Hash) (string, error) {
	switch h {
	case crypto.SHA256:
		return "sha256", nil
	case crypto.SHA384:
		return "sha384", nil
	case crypto.SHA512:
		return "sha512", nil
	default:
		return "", fmt.Errorf("gcp-kms: unsupported hash %q", h)
	}
}

// versionAlgorithm maps a trstctl algorithm to the Cloud KMS
// CryptoKeyVersionAlgorithm enum. The hash is bound into the key version's algorithm at
// creation time, so the conformance default (SHA-256) is used here; the RSA variants are
// PKCS#1 v1.5 to match the boundary's default RSA padding.
func versionAlgorithm(alg crypto.Algorithm) (string, error) {
	switch alg {
	case crypto.RSA2048:
		return "RSA_SIGN_PKCS1_2048_SHA256", nil
	case crypto.RSA3072:
		return "RSA_SIGN_PKCS1_3072_SHA256", nil
	case crypto.RSA4096:
		return "RSA_SIGN_PKCS1_4096_SHA256", nil
	case crypto.ECDSAP256:
		return "EC_SIGN_P256_SHA256", nil
	case crypto.ECDSAP384:
		return "EC_SIGN_P384_SHA384", nil
	default:
		return "", fmt.Errorf("gcp-kms: unsupported algorithm %q", alg)
	}
}
