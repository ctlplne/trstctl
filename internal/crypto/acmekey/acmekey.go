// SPDX-License-Identifier: BUSL-1.1

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
	"strings"
	"time"

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
// Challenge types this driver can be asked to solve. Strings rather than an
// enum so the seam carries no acme.* type in either direction (AN-3).
const (
	ChallengeHTTP01 = "http-01"
	ChallengeDNS01  = "dns-01"
)

// ChallengeRequest is one challenge to solve.
//
// Identifier keeps its leading "*." for a wildcard: the solver strips it when
// building the record name, and a solver that never saw the wildcard could not
// enforce a wildcard policy.
type ChallengeRequest struct {
	TenantID   string
	Type       string
	Identifier string
	Token      string
	// KeyAuth is the key authorization. RFC 8555 §8.1 makes it independent of
	// challenge type: HTTP-01 serves it verbatim, DNS-01 publishes its
	// SHA-256/base64url digest. The digest is computed and cross-checked inside
	// this boundary before the raw value crosses the seam.
	KeyAuth string
}

// ChallengeSolver satisfies challenges on behalf of the client.
//
// Solve returns a retract function rather than a separate Cleanup, so the
// caller cannot forget which challenge it is retracting and cannot retract one
// that was never presented. The previous shape — Present/Cleanup keyed by
// domain and token — allowed both.
type ChallengeSolver interface {
	// SolvableChallenges names the types this deployment can actually satisfy,
	// most preferred first. It is a census, not a wish: naming a type nothing
	// can solve makes the driver select it and then fail.
	SolvableChallenges() []string
	// Solve satisfies the challenge and returns a retract to undo it.
	Solve(ctx context.Context, req ChallengeRequest) (retract func(context.Context) error, err error)
}

// DVOutcome is one authorization's result, reported for observability.
type DVOutcome struct {
	Identifier    string
	ChallengeType string
	// Reused is true when the authority already considered the identifier
	// authorized and no challenge was solved. It is the number that matters as
	// validation-reuse windows compress: an install whose authorizations are
	// all reused has not proven it can still validate.
	Reused    bool
	ExpiresAt time.Time
}

// OrderRequest is one upstream order.
//
// A struct rather than positional arguments because the tenant had to be added
// and a positional parameter is exactly the kind of thing a caller drops — as
// the Let's Encrypt plugin did, discarding req.TenantID entirely before this.
type OrderRequest struct {
	TenantID string
	DNSNames []string
	CSR      []byte
}

// DVObserver receives every authorization outcome, including reused ones.
type DVObserver interface {
	ObserveAuthorization(ctx context.Context, tenantID string, out DVOutcome)
}

// ErrSolverNotConfigured is returned when a challenge must be solved and no
// solver was supplied. It fails closed: the previous behaviour substituted a
// no-op solver, which turned "this deployment cannot validate" into "validation
// silently did nothing".
var ErrSolverNotConfigured = errors.New("acmekey: no challenge solver is configured for this authority")

// ErrNoSolvableChallenge is returned when the authority offers no challenge
// type this deployment can satisfy.
var ErrNoSolvableChallenge = errors.New("acmekey: the authority offers no challenge this deployment can solve")

// Driver runs an ACME (RFC 8555) order to completion behind the crypto boundary.
// It wraps golang.org/x/crypto/acme so that callers (the Let's Encrypt CA plugin)
// drive an order using only neutral types — keeping the third-party ACME/crypto
// import inside internal/crypto (AN-3, CRYPTO-002).
type Driver struct {
	client   *acme.Client
	solver   ChallengeSolver
	observer DVObserver
}

// WithObserver attaches a DV observer. Separate from construction because the
// observer needs the store, which is assembled after the CA factories.
func (d *Driver) WithObserver(o DVObserver) *Driver {
	if d != nil {
		d.observer = o
	}
	return d
}

// newLocalDriverWithHTTPClient is a package-private protocol-test fixture. The
// shipped upstream-CA path cannot call it.
func newLocalDriverWithHTTPClient(directoryURL string, solver ChallengeSolver, httpClient *http.Client) (*Driver, error) {
	client, err := newLocalClientWithHTTPClient(directoryURL, httpClient)
	if err != nil {
		return nil, err
	}
	// A nil solver is STORED as nil and fails closed at the point of use. The
	// previous code substituted a no-op here, which is why an authority
	// offering a real challenge appeared to validate: nothing was presented,
	// the challenge was accepted, and the wait succeeded only because the
	// fixture pre-authorized the order.
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
	// A nil solver is STORED as nil and fails closed at the point of use. The
	// previous code substituted a no-op here, which is why an authority
	// offering a real challenge appeared to validate: nothing was presented,
	// the challenge was accepted, and the wait succeeded only because the
	// fixture pre-authorized the order.
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

// ErrIssuanceNotSubmitted proves this invocation stopped before calling the
// ACME finalize operation. Account/order/DNS preparation may have performed I/O,
// but no CSR was submitted for certificate signing. Never infer this from a
// timeout or an upstream error string after entering finalization (RFC8555 7.4).
var ErrIssuanceNotSubmitted = errors.New("acmekey: certificate finalization was not submitted")

// IssueChain registers the account, authorizes an order for dnsNames (solving any
// pending HTTP-01 challenges via the solver), finalizes it with csr, and returns
// the issued certificate chain as DER blocks (leaf first). The caller PEM-encodes
// the result; no acme.* type crosses this boundary.
func (d *Driver) IssueChain(ctx context.Context, req OrderRequest) (chain [][]byte, resultErr error) {
	finalizationStarted := false
	defer func() {
		if resultErr != nil && !finalizationStarted {
			resultErr = fmt.Errorf("%w: %w", ErrIssuanceNotSubmitted, resultErr)
		}
	}()
	if d == nil || d.client == nil {
		return nil, fmt.Errorf("acmekey: driver is destroyed")
	}
	// The tenant travels with the order because the solver needs it to select
	// a provider config under RLS (AN-1). It comes from the authenticated
	// principal upstream of here and is never a request field the caller
	// chooses; rejecting an empty one keeps a solver from ever running
	// unscoped.
	if strings.TrimSpace(req.TenantID) == "" {
		return nil, errors.New("acmekey: an order needs the tenant it is issued for")
	}
	dnsNames, csr := req.DNSNames, req.CSR
	// RFC 8555 returns the existing account when this key is already known and
	// x/crypto/acme surfaces that successful lookup as ErrAccountAlreadyExists.
	// Reusing one long-lived signer-backed account is the normal second-order and
	// retry path, not an issuance failure. Register still populates Client.KID
	// before returning this sentinel, so continuing is both safe and required.
	if _, err := d.client.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("acmekey: register: %w", err)
	}
	order, err := d.client.AuthorizeOrder(ctx, acme.DomainIDs(dnsNames...))
	if err != nil {
		return nil, fmt.Errorf("acmekey: authorize order: %w", err)
	}
	// Keep the URL from the create-order Location header. Poll responses are
	// not required to repeat Location, and x/crypto therefore returns a fresh
	// Order with an empty URI after WaitOrder. This stable handle is also what
	// lets us reconcile an ambiguous finalize without creating another order.
	orderURL := order.URI
	if order.Status != acme.StatusReady {
		if err := d.fulfill(ctx, req.TenantID, order); err != nil {
			return nil, err
		}
		if order, err = d.client.WaitOrder(ctx, orderURL); err != nil {
			return nil, fmt.Errorf("acmekey: wait order: %w", err)
		}
	} else {
		// A ready order means the authority reused EVERY authorization: no
		// challenge will be solved, and fulfill — which is where reuse used to
		// be recorded — never runs.
		//
		// That left the staleness surface blind in exactly the population it
		// exists for. An install whose validation path broke months ago keeps
		// getting ready orders and issuing happily; it is the one that finds
		// out for every identifier at once when the window closes. Recording
		// nothing for it meant the console showed an empty panel, which reads
		// as "no problems" and is the opposite of the truth.
		d.observeReusedOrder(ctx, req.TenantID, order)
	}
	finalizationStarted = true
	der, _, err := d.client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err == nil {
		return der, nil
	}

	// Finalize is a mutation: an error after sending it is ambiguous. In
	// particular, some ACME authorities answer an accepted asynchronous
	// finalize without a Location header. x/crypto/acme then cannot poll the
	// response order, even though the authority may already have minted the
	// certificate. Never create or finalize a replacement here. Reconcile the
	// original order URL returned by AuthorizeOrder and fetch its certificate
	// if the authority says that exact order is valid.
	finalizeErr := err
	reconciled, reconcileErr := d.client.WaitOrder(ctx, orderURL)
	if reconcileErr != nil || reconciled == nil || reconciled.Status != acme.StatusValid || reconciled.CertURL == "" {
		return nil, fmt.Errorf("acmekey: finalize: %w", finalizeErr)
	}
	der, fetchErr := d.client.FetchCert(ctx, reconciled.CertURL, true)
	if fetchErr != nil {
		return nil, fmt.Errorf("acmekey: finalize: reconciled order certificate fetch failed: %w", fetchErr)
	}
	return der, nil
}

// observeReusedOrder records every authorization of an already-ready order.
//
// Best-effort by design: this is reporting, and failing an issuance the
// authority has already approved because a follow-up read failed would trade a
// working certificate for a log line. A fetch that fails records nothing, which
// is honest — absence of an observation, not a fabricated one.
func (d *Driver) observeReusedOrder(ctx context.Context, tenantID string, order *acme.Order) {
	if d.observer == nil {
		return
	}
	for _, authzURL := range order.AuthzURLs {
		authz, err := d.client.GetAuthorization(ctx, authzURL)
		if err != nil {
			continue
		}
		d.observe(ctx, tenantID, DVOutcome{
			Identifier: identifierOf(authz), Reused: true, ExpiresAt: authz.Expires,
		})
	}
}

// fulfill solves the pending authorizations of an order via the configured
// HTTP-01 solver, then accepts each challenge and waits for it to validate.
func (d *Driver) fulfill(ctx context.Context, tenantID string, order *acme.Order) error {
	for _, authzURL := range order.AuthzURLs {
		authz, err := d.client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return fmt.Errorf("acmekey: get authorization: %w", err)
		}
		if authz.Status == acme.StatusValid {
			// Already authorized: the authority is reusing a previous
			// validation. Reported rather than skipped silently — as reuse
			// windows compress, an install whose authorizations are all reused
			// has not demonstrated it can still validate, and the day the
			// window closes it discovers that all at once.
			d.observe(ctx, tenantID, DVOutcome{
				Identifier: identifierOf(authz), Reused: true, ExpiresAt: authz.Expires,
			})
			continue
		}
		if d.solver == nil {
			return ErrSolverNotConfigured
		}
		chal := selectChallenge(authz, d.solver.SolvableChallenges())
		if chal == nil {
			return fmt.Errorf("%w: authorization %s offers [%s], this deployment can solve [%s]",
				ErrNoSolvableChallenge, identifierOf(authz),
				strings.Join(offeredTypes(authz), ", "),
				strings.Join(d.solver.SolvableChallenges(), ", "))
		}
		// The key authorization is challenge-type independent (RFC 8555 §8.1).
		// x/crypto/acme names this HTTP01ChallengeResponse, which is
		// misleading: DNS-01 publishes its digest rather than the value
		// itself, but the value is the same.
		keyAuth, err := d.client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return err
		}
		if chal.Type == ChallengeDNS01 {
			// Cross-check the digest the solver will publish against the one
			// this library computes, INSIDE the boundary. That is what licenses
			// passing the raw key authorization across the seam: the solver can
			// hash it with the platform's own helper and cannot disagree
			// without this failing first.
			want, derr := d.client.DNS01ChallengeRecord(chal.Token)
			if derr != nil {
				return fmt.Errorf("acmekey: dns-01 record: %w", derr)
			}
			if got := boundary.SHA256Base64URL([]byte(keyAuth)); got != want {
				return errors.New("acmekey: dns-01 digest disagreement; refusing to publish a record " +
					"the authority will not accept")
			}
		}

		retract, err := d.solver.Solve(ctx, ChallengeRequest{
			TenantID: tenantID, Type: chal.Type, Identifier: identifierOf(authz),
			Token: chal.Token, KeyAuth: keyAuth,
		})
		if err != nil {
			return fmt.Errorf("acmekey: present %s challenge for %s: %w", chal.Type, identifierOf(authz), err)
		}
		// Retract on EVERY exit path, not only the happy one. The previous code
		// returned early on Accept or WaitAuthorization failure without
		// cleaning up and discarded the cleanup error entirely. Harmless for an
		// in-memory HTTP-01 file; for DNS it leaves a live public TXT record
		// with a validation token in it, indefinitely.
		//
		// WithoutCancel because the retraction must still run when the order
		// failed because ctx expired — that is exactly when a record is most
		// likely to be left behind.
		err = func() (err error) {
			defer func() {
				if retract == nil {
					return
				}
				if rerr := retract(context.WithoutCancel(ctx)); rerr != nil {
					err = errors.Join(err, fmt.Errorf("acmekey: retract %s challenge: %w", chal.Type, rerr))
				}
			}()
			if _, aerr := d.client.Accept(ctx, chal); aerr != nil {
				return fmt.Errorf("acmekey: accept challenge: %w", aerr)
			}
			final, werr := d.client.WaitAuthorization(ctx, authzURL)
			if werr != nil {
				return fmt.Errorf("acmekey: wait authorization: %w", werr)
			}
			d.observe(ctx, tenantID, DVOutcome{
				Identifier: identifierOf(authz), ChallengeType: chal.Type,
				Reused: false, ExpiresAt: final.Expires,
			})
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// selectChallenge picks the first offered challenge whose type this deployment
// can solve, in the solver's own order of preference.
func selectChallenge(authz *acme.Authorization, prefer []string) *acme.Challenge {
	for _, want := range prefer {
		for _, c := range authz.Challenges {
			if c.Type == want {
				return c
			}
		}
	}
	return nil
}

func offeredTypes(authz *acme.Authorization) []string {
	out := make([]string, 0, len(authz.Challenges))
	for _, c := range authz.Challenges {
		out = append(out, c.Type)
	}
	return out
}

// identifierOf returns the authorization's identifier, restoring the "*."
// prefix for a wildcard. x/crypto/acme reports the base name plus a Wildcard
// flag; a solver enforcing a wildcard policy needs to see the wildcard.
func identifierOf(authz *acme.Authorization) string {
	if authz.Wildcard {
		return "*." + authz.Identifier.Value
	}
	return authz.Identifier.Value
}

func (d *Driver) observe(ctx context.Context, tenantID string, out DVOutcome) {
	if d.observer == nil {
		return
	}
	d.observer.ObserveAuthorization(ctx, tenantID, out)
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
		// The outbox may retry after the CA accepted revocation but before local
		// completion committed. RFC 8555's exact alreadyRevoked problem confirms
		// the requested terminal state; other 4xx failures are not success.
		var problem *acme.Error
		if errors.As(err, &problem) && problem.ProblemType == "urn:ietf:params:acme:error:alreadyRevoked" {
			return nil
		}
		return fmt.Errorf("acmekey: revoke: %w", err)
	}
	return nil
}
