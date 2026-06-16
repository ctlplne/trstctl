// Package azurekv is the Azure Key Vault (keys) key-management backend (S9.4), built from
// the S9.1 backend template behind the AN-3 crypto boundary. GenerateKey creates an
// asymmetric key in the vault and returns a crypto.Signer that signs via the Key Vault
// /sign API — the private key never leaves the vault. Digests route through internal/crypto
// (no crypto/*); requests authenticate with an AAD bearer token supplied by the caller.
//
// It speaks the Key Vault REST wire protocol directly over an injectable HTTP doer so it is
// exercised against a faithful in-process double on CI; real-backend validation is deferred
// (the same pattern Phase 1 used for the cloud connectors).
//
// NOTE ON PUBLIC KEYS: real Azure Key Vault returns a key's public material as a JWK, not as
// a DER SubjectPublicKeyInfo. Converting JWK->SPKI without importing crypto/* (AN-3) is out
// of scope for this sprint; the double therefore returns base64-std DER directly and the
// create/get responses are modeled to carry that DER. JWK->SPKI conversion is a deferred
// follow-up.
package azurekv

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/crypto"
)

// apiVersion is the Key Vault data-plane REST API version exercised here.
const apiVersion = "7.4"

// defaultOpTimeout bounds a single Key Vault network operation when the caller
// does not supply its own deadline, so an interface-forced context.Background()
// cannot hang a worker on a wedged vault (CODE-002).
const defaultOpTimeout = 30 * time.Second

// Credentials carry the AAD access (bearer) token used to authenticate requests. The token
// is supplied by the caller (no OAuth flow is performed here); it is opaque and never logged.
type Credentials struct {
	BearerToken string
}

// HTTPDoer is the minimal HTTP client seam (tests inject the double's client).
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Backend is an Azure Key Vault (keys) crypto.Backend.
type Backend struct {
	vaultURL  string
	endpoint  string
	creds     Credentials
	doer      HTTPDoer
	n         int
	opTimeout time.Duration
}

var (
	_ crypto.Backend             = (*Backend)(nil)
	_ crypto.ContextKeyGenerator = (*Backend)(nil)
	_ crypto.ContextSigner       = (*kvSigner)(nil)
)

// Option configures a Backend.
type Option func(*Backend)

// WithEndpoint overrides the vault endpoint requests are sent to (tests, sovereign clouds).
// The default is the vault URL passed to New.
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

// New returns an Azure Key Vault backend for vaultURL (e.g. https://my-vault.vault.azure.net),
// authenticating with creds.
func New(vaultURL string, creds Credentials, opts ...Option) *Backend {
	b := &Backend{
		vaultURL:  strings.TrimRight(vaultURL, "/"),
		creds:     creds,
		doer:      http.DefaultClient,
		opTimeout: defaultOpTimeout,
	}
	b.endpoint = b.vaultURL
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
func (b *Backend) Name() string { return "azure-key-vault" }

// GenerateKey creates an asymmetric signing key in the vault and returns a Signer for it.
// It is the context-less entry point; it applies the backend's per-operation timeout
// floor so a wedged vault cannot hang the caller (CODE-002). Callers holding a context
// should prefer GenerateKeyContext.
func (b *Backend) GenerateKey(alg crypto.Algorithm) (crypto.Signer, error) {
	return b.GenerateKeyContext(context.Background(), alg)
}

// GenerateKeyContext is the context-bearing key generation (crypto.ContextKeyGenerator):
// the caller's context bounds and can cancel every vault round-trip the generation makes.
func (b *Backend) GenerateKeyContext(ctx context.Context, alg crypto.Algorithm) (crypto.Signer, error) {
	body, err := createBody(alg)
	if err != nil {
		return nil, err
	}
	b.n++
	name := fmt.Sprintf("trstctl-key-%d", b.n)
	ctx, cancel := b.opContext(ctx)
	defer cancel()
	// The create response models both the key identifier and (per the package note) the
	// base64-std DER SubjectPublicKeyInfo the double provides.
	var created struct {
		Key struct {
			Kid string `json:"kid"`
		} `json:"key"`
		DER string `json:"der"`
	}
	path := fmt.Sprintf("/keys/%s/create", name)
	if err := b.call(ctx, http.MethodPost, path, body, &created); err != nil {
		return nil, fmt.Errorf("azure-key-vault: create key: %w", err)
	}
	keyName, version := keyNameAndVersion(created.Key.Kid, name)
	pub, err := b.publicKey(ctx, keyName, version, alg, created.DER)
	if err != nil {
		return nil, err
	}
	return &kvSigner{b: b, name: keyName, version: version, alg: alg, pub: pub}, nil
}

// publicKey resolves the key's DER SubjectPublicKeyInfo. If the create response already
// carried it, that is used; otherwise the key is fetched.
func (b *Backend) publicKey(ctx context.Context, name, version string, alg crypto.Algorithm, derB64 string) (crypto.PublicKey, error) {
	if derB64 == "" {
		var out struct {
			DER string `json:"der"`
		}
		path := keyPath(name, version)
		if err := b.call(ctx, http.MethodGet, path, nil, &out); err != nil {
			return crypto.PublicKey{}, fmt.Errorf("azure-key-vault: get public key: %w", err)
		}
		derB64 = out.DER
	}
	der, err := base64.StdEncoding.DecodeString(derB64)
	if err != nil {
		return crypto.PublicKey{}, fmt.Errorf("azure-key-vault: decode public key: %w", err)
	}
	return crypto.PublicKey{Algorithm: alg, DER: der}, nil
}

// kvSigner signs a digest via the Key Vault /sign API; the key never leaves the vault.
type kvSigner struct {
	b       *Backend
	name    string
	version string
	alg     crypto.Algorithm
	pub     crypto.PublicKey
}

func (s *kvSigner) Public() crypto.PublicKey    { return s.pub }
func (s *kvSigner) Algorithm() crypto.Algorithm { return s.alg }

// Sign is the context-less entry point; it applies the backend's per-operation
// timeout floor so a wedged vault cannot hang the caller (CODE-002). Callers
// holding a context should prefer SignContext.
func (s *kvSigner) Sign(message []byte, opts crypto.SignOptions) ([]byte, error) {
	return s.SignContext(context.Background(), message, opts)
}

// SignContext is the context-bearing signing operation (crypto.ContextSigner): the
// caller's context bounds and can cancel the remote Key Vault /sign call.
func (s *kvSigner) SignContext(ctx context.Context, message []byte, opts crypto.SignOptions) ([]byte, error) {
	digest, err := crypto.Digest(hashOf(opts), message)
	if err != nil {
		return nil, err
	}
	joseAlg, err := signingAlgorithm(s.alg, opts)
	if err != nil {
		return nil, err
	}
	// Key Vault uses base64url (no padding) for both the digest value and the signature.
	body, err := json.Marshal(map[string]string{
		"alg":   joseAlg,
		"value": base64.RawURLEncoding.EncodeToString(digest),
	})
	if err != nil {
		return nil, err
	}
	ctx, cancel := s.b.opContext(ctx)
	defer cancel()
	var out struct {
		Value string `json:"value"`
	}
	path := keyPath(s.name, s.version) + "/sign"
	if err := s.b.call(ctx, http.MethodPost, path, body, &out); err != nil {
		return nil, fmt.Errorf("azure-key-vault: sign: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(out.Value)
	if err != nil {
		return nil, fmt.Errorf("azure-key-vault: decode signature: %w", err)
	}
	return sig, nil
}

// call performs a bearer-authenticated Key Vault REST request and decodes the JSON response.
// The api-version query parameter is appended to every request. The provider-specific
// parts (URL + api-version, the Bearer/Accept headers) stay here; the shared round-trip —
// bounded read, non-2xx normalisation, JSON decode — is internal/cloudhttp (CODE-006). The
// per-op timeout is already applied by the caller via withTimeout(ctx) (CODE-002).
func (b *Backend) call(ctx context.Context, method, path string, body []byte, out any) error {
	u := b.endpoint + path + "?api-version=" + apiVersion
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	// Bearer auth: the AAD access token authenticates every request.
	req.Header.Set("Authorization", "Bearer "+b.creds.BearerToken)
	if err := cloudhttp.JSON(b.doer, req, out); err != nil {
		return fmt.Errorf("azure-key-vault: %w", err)
	}
	return nil
}

// keyPath returns the data-plane path for a specific key version, or the unversioned key path
// when version is empty.
func keyPath(name, version string) string {
	if version == "" {
		return "/keys/" + name
	}
	return "/keys/" + name + "/" + version
}

// keyNameAndVersion extracts the key name and version from a Key Vault key identifier
// (https://<vault>/keys/<name>/<version>). It falls back to the requested name and an empty
// version when the identifier is absent or unparseable.
func keyNameAndVersion(kid, fallbackName string) (name, version string) {
	name, version = fallbackName, ""
	if kid == "" {
		return name, version
	}
	parts := strings.Split(strings.Trim(kid, "/"), "/")
	for i, p := range parts {
		if p == "keys" && i+1 < len(parts) {
			name = parts[i+1]
			if i+2 < len(parts) {
				version = parts[i+2]
			}
			break
		}
	}
	return name, version
}

func hashOf(opts crypto.SignOptions) crypto.Hash {
	if opts.Hash == "" {
		return crypto.SHA256
	}
	return opts.Hash
}

// createBody builds the JSON body for the Key Vault create-key request for alg.
func createBody(alg crypto.Algorithm) ([]byte, error) {
	switch alg {
	case crypto.RSA2048:
		return json.Marshal(map[string]any{"kty": "RSA", "key_size": 2048})
	case crypto.RSA3072:
		return json.Marshal(map[string]any{"kty": "RSA", "key_size": 3072})
	case crypto.RSA4096:
		return json.Marshal(map[string]any{"kty": "RSA", "key_size": 4096})
	case crypto.ECDSAP256:
		return json.Marshal(map[string]any{"kty": "EC", "crv": "P-256"})
	case crypto.ECDSAP384:
		return json.Marshal(map[string]any{"kty": "EC", "crv": "P-384"})
	case crypto.ECDSAP521:
		return json.Marshal(map[string]any{"kty": "EC", "crv": "P-521"})
	default:
		return nil, fmt.Errorf("azure-key-vault: unsupported algorithm %q", alg)
	}
}

// signingAlgorithm maps a trstctl algorithm + options to the JOSE algorithm Key Vault names.
// Key Vault's RSA /sign uses PKCS#1 v1.5 (RSnnn) or PSS (PSnnn); ECDSA uses ESnnn.
func signingAlgorithm(alg crypto.Algorithm, opts crypto.SignOptions) (string, error) {
	suffix := map[crypto.Hash]string{crypto.SHA256: "256", crypto.SHA384: "384", crypto.SHA512: "512"}[hashOf(opts)]
	if suffix == "" {
		return "", fmt.Errorf("azure-key-vault: unsupported hash %q", opts.Hash)
	}
	switch alg {
	case crypto.RSA2048, crypto.RSA3072, crypto.RSA4096:
		if opts.RSAPadding == crypto.RSAPSS {
			return "PS" + suffix, nil
		}
		return "RS" + suffix, nil
	case crypto.ECDSAP256, crypto.ECDSAP384, crypto.ECDSAP521:
		return "ES" + suffix, nil
	default:
		return "", fmt.Errorf("azure-key-vault: unsupported algorithm %q", alg)
	}
}
