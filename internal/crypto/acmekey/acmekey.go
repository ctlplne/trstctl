// SPDX-License-Identifier: MPL-2.0

// Package acmekey builds ACME clients inside the AN-3 crypto boundary (a
// subpackage of internal/crypto). The shipped client adapts an isolated-process
// DigestSigner to the crypto.Signer contract required by x/crypto/acme, so the
// control plane sees only the account public key and signatures. Legacy local
// constructors remain for protocol tests and embedded ACME-server fixtures.
//
// It also wraps the golang.org/x/crypto/acme order-driving flow behind a Driver
// with neutral (non-acme.*) types, so the Let's Encrypt CA plugin can run an ACME
// order without importing golang.org/x/crypto/acme itself. AN-3 forbids stdlib
// crypto/* outside this boundary and — to keep the contract whole — third-party
// crypto modules (golang.org/x/crypto, github.com/cloudflare/circl) too; routing
// the ACME client and its order flow through here keeps the only third-party-crypto
// import for issuance inside the boundary (CRYPTO-002).
package acmekey

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/crypto/acme"

	boundary "trstctl.com/trstctl/internal/crypto"
)

// NewClient returns an ACME client for the directory at directoryURL, with a
// freshly generated ECDSA P-256 account key. It exists only as an RFC 8555 test
// client for trstctl's own ACME server; a repository guard forbids production
// callers. Upstream-CA production code uses NewDriverWithDigestSigner.
func NewClient(directoryURL string) (*acme.Client, error) {
	return newLocalClientWithHTTPClient(directoryURL, nil)
}

func newLocalClientWithHTTPClient(directoryURL string, httpClient *http.Client) (*acme.Client, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &acme.Client{Key: key, HTTPClient: httpClient, DirectoryURL: directoryURL}, nil
}

// NewClientWithDigestSigner builds an ACME client whose account key is only a
// public-key plus remote digest-signing handle. The private key operation stays
// behind the AN-4 signing-service transport; this process never receives an
// ECDSA private scalar. The adapter itself lives in the crypto boundary because
// golang.org/x/crypto/acme requires the standard-library crypto.Signer shape.
func NewClientWithDigestSigner(directoryURL string, httpClient *http.Client, signer boundary.DigestSigner) (*acme.Client, error) {
	key, err := newDigestSignerAdapter(signer)
	if err != nil {
		return nil, err
	}
	return &acme.Client{Key: key, HTTPClient: httpClient, DirectoryURL: directoryURL}, nil
}

type digestSignerAdapter struct {
	signer boundary.DigestSigner
	public stdcrypto.PublicKey
}

var _ stdcrypto.Signer = (*digestSignerAdapter)(nil)

func newDigestSignerAdapter(signer boundary.DigestSigner) (*digestSignerAdapter, error) {
	if signer == nil {
		return nil, fmt.Errorf("acmekey: remote account signer is required")
	}
	if signer.Algorithm() != boundary.ECDSAP256 {
		return nil, fmt.Errorf("acmekey: remote account signer must use ECDSA-P256")
	}
	public, err := x509.ParsePKIXPublicKey(signer.Public().DER)
	if err != nil {
		return nil, fmt.Errorf("acmekey: parse remote account public key: %w", err)
	}
	ecdsaPublic, ok := public.(*ecdsa.PublicKey)
	if !ok || ecdsaPublic.Curve != elliptic.P256() {
		return nil, fmt.Errorf("acmekey: remote account public key is not ECDSA-P256")
	}
	return &digestSignerAdapter{signer: signer, public: ecdsaPublic}, nil
}

func (s *digestSignerAdapter) Public() stdcrypto.PublicKey { return s.public }

func (s *digestSignerAdapter) Sign(_ io.Reader, digest []byte, opts stdcrypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != stdcrypto.SHA256 || len(digest) != stdcrypto.SHA256.Size() {
		return nil, fmt.Errorf("acmekey: ACME account signing requires one SHA-256 digest")
	}
	return s.signer.SignDigest(digest, boundary.SignOptions{Hash: boundary.SHA256})
}

// NewRSAClient returns an RFC 8555 test client with a freshly generated RSA
// account key (RS256 JWS). A repository guard forbids production callers.
func NewRSAClient(directoryURL string) (*acme.Client, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &acme.Client{Key: key, DirectoryURL: directoryURL}, nil
}

// ChallengeSolver provisions and removes the response for an ACME HTTP-01
// challenge. It is a neutral seam (no acme.* types), so an ACME CA plugin can
// supply one without importing golang.org/x/crypto/acme.
type ChallengeSolver interface {
	Present(domain, token, keyAuth string) error
	Cleanup(domain, token string) error
}

// Driver runs an ACME (RFC 8555) order to completion behind the crypto boundary.
// It wraps golang.org/x/crypto/acme so that callers (the Let's Encrypt CA plugin)
// drive an order using only neutral types — keeping the third-party ACME/crypto
// import inside internal/crypto (AN-3, CRYPTO-002).
type Driver struct {
	client *acme.Client
	solver ChallengeSolver
}

// newLocalDriverWithHTTPClient is a package-private protocol-test fixture. The
// shipped upstream-CA path cannot call it.
func newLocalDriverWithHTTPClient(directoryURL string, solver ChallengeSolver, httpClient *http.Client) (*Driver, error) {
	client, err := newLocalClientWithHTTPClient(directoryURL, httpClient)
	if err != nil {
		return nil, err
	}
	if solver == nil {
		solver = noopSolver{}
	}
	return &Driver{client: client, solver: solver}, nil
}

// NewDriverWithDigestSigner is the production AN-4 constructor. It drives the
// same x/crypto/acme state machine and exact JWS encoding as NewDriver, but every
// account signature crosses a boundary.DigestSigner instead of using a private
// key in this process.
func NewDriverWithDigestSigner(directoryURL string, solver ChallengeSolver, httpClient *http.Client, signer boundary.DigestSigner) (*Driver, error) {
	client, err := NewClientWithDigestSigner(directoryURL, httpClient, signer)
	if err != nil {
		return nil, err
	}
	if solver == nil {
		solver = noopSolver{}
	}
	return &Driver{client: client, solver: solver}, nil
}

// Destroy makes the driver fail closed and drops its account-key adapter. A
// locally generated test key is explicitly zeroed; a remote adapter contains no
// private scalar and is simply released while the signer retains account custody.
func (d *Driver) Destroy() {
	if d == nil || d.client == nil {
		return
	}
	key, _ := d.client.Key.(*ecdsa.PrivateKey)
	d.client.Key = nil
	d.client = nil
	boundary.WipeECDSAPrivateKey(key)
}

type noopSolver struct{}

func (noopSolver) Present(string, string, string) error { return nil }
func (noopSolver) Cleanup(string, string) error         { return nil }

// IssueChain registers the account, authorizes an order for dnsNames (solving any
// pending HTTP-01 challenges via the solver), finalizes it with csr, and returns
// the issued certificate chain as DER blocks (leaf first). The caller PEM-encodes
// the result; no acme.* type crosses this boundary.
func (d *Driver) IssueChain(ctx context.Context, dnsNames []string, csr []byte) ([][]byte, error) {
	if d == nil || d.client == nil {
		return nil, fmt.Errorf("acmekey: driver is destroyed")
	}
	if _, err := d.client.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil {
		return nil, fmt.Errorf("acmekey: register: %w", err)
	}
	order, err := d.client.AuthorizeOrder(ctx, acme.DomainIDs(dnsNames...))
	if err != nil {
		return nil, fmt.Errorf("acmekey: authorize order: %w", err)
	}
	if order.Status != acme.StatusReady {
		if err := d.fulfill(ctx, order); err != nil {
			return nil, err
		}
		if order, err = d.client.WaitOrder(ctx, order.URI); err != nil {
			return nil, fmt.Errorf("acmekey: wait order: %w", err)
		}
	}
	der, _, err := d.client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("acmekey: finalize: %w", err)
	}
	return der, nil
}

// fulfill solves the pending authorizations of an order via the configured
// HTTP-01 solver, then accepts each challenge and waits for it to validate.
func (d *Driver) fulfill(ctx context.Context, order *acme.Order) error {
	for _, authzURL := range order.AuthzURLs {
		authz, err := d.client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return fmt.Errorf("acmekey: get authorization: %w", err)
		}
		if authz.Status == acme.StatusValid {
			continue
		}
		chal := httpChallenge(authz)
		if chal == nil {
			return fmt.Errorf("acmekey: authorization %s offers no http-01 challenge", authz.Identifier.Value)
		}
		response, err := d.client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return err
		}
		if err := d.solver.Present(authz.Identifier.Value, chal.Token, response); err != nil {
			return fmt.Errorf("acmekey: present challenge: %w", err)
		}
		if _, err := d.client.Accept(ctx, chal); err != nil {
			return fmt.Errorf("acmekey: accept challenge: %w", err)
		}
		if _, err := d.client.WaitAuthorization(ctx, authzURL); err != nil {
			return fmt.Errorf("acmekey: wait authorization: %w", err)
		}
		_ = d.solver.Cleanup(authz.Identifier.Value, chal.Token)
	}
	return nil
}

func httpChallenge(authz *acme.Authorization) *acme.Challenge {
	for _, c := range authz.Challenges {
		if c.Type == "http-01" {
			return c
		}
	}
	return nil
}

// RevokeChain revokes a certificate through the ACME authority (epic R2,
// RFC 8555 §7.6).
//
// It lives here rather than in the issuer package for the same reason
// IssueChain does: the request is JWS-signed with the account key, and account
// keys stay behind the AN-3 boundary. The issuer package hands over the
// certificate and a reason and never touches a key.
//
// ACME identifies the certificate by its DER, not by serial — the protocol has
// no serial-based revocation — so the caller must supply the certificate
// itself. That is a real constraint on the operation, not an implementation
// choice: trstctl cannot revoke an ACME certificate it does not hold a copy of.
func (d *Driver) RevokeChain(ctx context.Context, certDER []byte, reason int) error {
	if d == nil || d.client == nil {
		return errors.New("acmekey: driver is destroyed")
	}
	if len(certDER) == 0 {
		return errors.New("acmekey: ACME revocation identifies the certificate by its bytes; none supplied")
	}
	// The account key authorizes the revocation. acme.CRLReasonUnspecified is
	// the protocol default when a caller supplies no meaningful reason; passing
	// a reason the authority rejects would fail the whole call, so an
	// out-of-range value is normalized rather than sent.
	crlReason := acme.CRLReasonCode(reason)
	if reason < 0 || reason > 10 {
		crlReason = acme.CRLReasonUnspecified
	}
	if err := d.client.RevokeCert(ctx, nil, certDER, crlReason); err != nil {
		return fmt.Errorf("acmekey: revoke: %w", err)
	}
	return nil
}
