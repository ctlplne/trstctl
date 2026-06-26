// Package awskms is the AWS KMS key-management backend (KMS-04), behind the AN-3
// crypto boundary. GenerateKey creates an asymmetric KMS key (KeyUsage SIGN_VERIFY)
// and returns a crypto.Signer that signs via the AWS KMS Sign API; the private key
// never leaves KMS.
//
// The backend is assembled with the official AWS SDK v2 KMS client and then exposed
// through trstctl's compile-time Go interfaces plus dependency injection. That is
// the generic prior-art shape used by crypto.Signer, Java JCA, OpenSSL ENGINE, and
// PKCS#11: no runtime crypto engine, no Go plugin/DLL provider loading, and no
// runtime registration of crypto suites.
package awskms

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awskmssdk "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/secrettext"
)

// Credentials are the AWS access credentials used to sign requests. SessionToken is set
// for temporary (STS/role) credentials. They are opaque here, never logged.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey []byte
	SessionToken    []byte
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
	creds     Credentials
	doer      HTTPDoer
	opTimeout time.Duration
	client    *awskmssdk.Client
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
	creds.SecretAccessKey = secrettext.Clone(creds.SecretAccessKey)
	creds.SessionToken = secrettext.Clone(creds.SessionToken)
	b := &Backend{region: region, creds: creds, doer: http.DefaultClient, opTimeout: defaultOpTimeout}
	for _, o := range opts {
		o(b)
	}
	b.client = b.sdkClient()
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
}

func (b *Backend) sdkClient() *awskmssdk.Client {
	// The AWS SDK credential provider requires string-valued credentials. trstctl
	// keeps config/file material as []byte until this SDK edge and never logs or
	// returns it; AWS's provider owns the unavoidable edge string after this point.
	cfg := awssdk.Config{
		Region: b.region,
		Credentials: awssdk.NewCredentialsCache(credentials.NewStaticCredentialsProvider(
			b.creds.AccessKeyID,
			secrettext.String(b.creds.SecretAccessKey),
			secrettext.String(b.creds.SessionToken),
		)),
		HTTPClient: b.doer,
	}
	return awskmssdk.NewFromConfig(cfg, func(o *awskmssdk.Options) {
		if b.endpoint != "" {
			o.BaseEndpoint = awssdk.String(b.endpoint)
		}
	})
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
	created, err := b.client.CreateKey(ctx, &awskmssdk.CreateKeyInput{
		KeySpec:  spec,
		KeyUsage: types.KeyUsageTypeSignVerify,
	})
	if err != nil {
		return nil, fmt.Errorf("aws-kms: create key: %w", err)
	}
	if created.KeyMetadata == nil || awssdk.ToString(created.KeyMetadata.KeyId) == "" {
		return nil, fmt.Errorf("aws-kms: create key returned no key id")
	}
	keyID := awssdk.ToString(created.KeyMetadata.KeyId)
	pub, err := b.publicKey(ctx, keyID, alg)
	if err != nil {
		return nil, err
	}
	return &kmsSigner{b: b, keyID: keyID, alg: alg, pub: pub}, nil
}

func (b *Backend) publicKey(ctx context.Context, keyID string, alg crypto.Algorithm) (crypto.PublicKey, error) {
	out, err := b.client.GetPublicKey(ctx, &awskmssdk.GetPublicKeyInput{KeyId: awssdk.String(keyID)})
	if err != nil {
		return crypto.PublicKey{}, fmt.Errorf("aws-kms: get public key: %w", err)
	}
	if len(out.PublicKey) == 0 {
		return crypto.PublicKey{}, fmt.Errorf("aws-kms: get public key returned no material")
	}
	return crypto.PublicKey{Algorithm: alg, DER: append([]byte(nil), out.PublicKey...)}, nil
}

// kmsSigner signs a digest via the KMS Sign API; the private key never leaves KMS.
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
	out, err := s.b.client.Sign(ctx, &awskmssdk.SignInput{
		KeyId:            awssdk.String(s.keyID),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: sa,
	})
	if err != nil {
		return nil, fmt.Errorf("aws-kms: sign: %w", err)
	}
	if len(out.Signature) == 0 {
		return nil, fmt.Errorf("aws-kms: sign returned no signature")
	}
	return append([]byte(nil), out.Signature...), nil
}

func hashOf(opts crypto.SignOptions) crypto.Hash {
	if opts.Hash == "" {
		return crypto.SHA256
	}
	return opts.Hash
}

func keySpec(alg crypto.Algorithm) (types.KeySpec, error) {
	switch alg {
	case crypto.RSA2048:
		return types.KeySpecRsa2048, nil
	case crypto.RSA3072:
		return types.KeySpecRsa3072, nil
	case crypto.RSA4096:
		return types.KeySpecRsa4096, nil
	case crypto.ECDSAP256:
		return types.KeySpecEccNistP256, nil
	case crypto.ECDSAP384:
		return types.KeySpecEccNistP384, nil
	case crypto.ECDSAP521:
		return types.KeySpecEccNistP521, nil
	default:
		return "", fmt.Errorf("aws-kms: unsupported algorithm %q", alg)
	}
}

func signingAlgorithm(alg crypto.Algorithm, opts crypto.SignOptions) (types.SigningAlgorithmSpec, error) {
	suffix := map[crypto.Hash]string{crypto.SHA256: "SHA_256", crypto.SHA384: "SHA_384", crypto.SHA512: "SHA_512"}[hashOf(opts)]
	if suffix == "" {
		return "", fmt.Errorf("aws-kms: unsupported hash %q", opts.Hash)
	}
	switch alg {
	case crypto.RSA2048, crypto.RSA3072, crypto.RSA4096:
		if opts.RSAPadding == crypto.RSAPSS {
			return types.SigningAlgorithmSpec("RSASSA_PSS_" + suffix), nil
		}
		return types.SigningAlgorithmSpec("RSASSA_PKCS1_V1_5_" + suffix), nil
	case crypto.ECDSAP256, crypto.ECDSAP384, crypto.ECDSAP521:
		return types.SigningAlgorithmSpec("ECDSA_" + suffix), nil
	default:
		return "", fmt.Errorf("aws-kms: unsupported algorithm %q", alg)
	}
}
