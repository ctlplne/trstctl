// SPDX-License-Identifier: MPL-2.0

// Package letsencrypt is the first CA plugin: an ACME (RFC 8555) certificate
// authority — Let's Encrypt or any ACME CA — implementing the ca.CA interface.
// It drives the order through the crypto boundary's acmekey.Driver (which wraps
// golang.org/x/crypto/acme) and finalizes with the caller's CSR. The ACME account
// JWS adapter and the whole ACME/crypto dependency live behind the crypto
// boundary (internal/crypto/acmekey). The shipped constructor backs that adapter
// with the isolated signing process, so this package holds neither account-key
// private material nor crypto/* imports (AN-3/AN-4/AN-8, CRYPTO-002).
//
// On the platform it runs behind ca.IssuanceService, which gives it idempotency
// (AN-5, no double-mint on retry) and an outbox record (AN-6, observability); the
// signer custodies the ACME account key (AN-4), while the upstream CA signs the
// requested certificate.
package letsencrypt

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/protocols/acme"
)

// Plugin is an ACME CA plugin.
type Plugin struct {
	name   string
	driver *acmekey.Driver
}

var _ ca.CA = (*Plugin)(nil)

// NewPluginWithRemoteAccountSigner is the production constructor. The ACME
// protocol still runs through x/crypto/acme, but the account JWS key is an
// opaque digest signer backed by the isolated signing process (AN-4/AN-8).
func NewPluginWithRemoteAccountSigner(name, directoryURL string, client *http.Client, signer crypto.DigestSigner, opts ...Option) (*Plugin, error) {
	var cfg options
	for _, o := range opts {
		o(&cfg)
	}
	// A nil solver stays nil. The driver fails closed when an authority
	// actually requires validation, which is the honest behaviour for a
	// deployment that has configured no DNS-01 provider — the previous no-op
	// substitution made that state indistinguishable from a working one.
	driver, err := acmekey.NewDriverWithDigestSigner(directoryURL, cfg.solver, client, signer)
	if err != nil {
		return nil, err
	}
	if cfg.observer != nil {
		driver = driver.WithObserver(cfg.observer)
	}
	return &Plugin{name: name, driver: driver}, nil
}

// Option configures the plugin. Variadic rather than a new constructor because
// internal/crypto/acmekey/production_guard_test.go bans a second constructor
// name in production code, and the guard is right: two constructors is how one
// of them quietly becomes the one nobody wires a solver into.
type Option func(*options)

type options struct {
	solver   acmekey.ChallengeSolver
	observer acmekey.DVObserver
}

// WithChallengeSolver supplies the domain-validation solver (epic B7). Without
// one this issuer can only obtain certificates for identifiers the authority
// has already authorized.
func WithChallengeSolver(s acmekey.ChallengeSolver) Option {
	return func(o *options) { o.solver = s }
}

// WithDVObserver receives every authorization outcome, including ones the
// authority reused without a challenge.
func WithDVObserver(o acmekey.DVObserver) Option {
	return func(opt *options) { opt.observer = o }
}

// Name identifies the authority.
func (p *Plugin) Name() string { return p.name }

// Destroy releases the ACME client. Local/test constructors also zero their
// process-local account scalar; the shipped remote constructor only drops its
// public-key/transport adapter because signer custody remains out of process.
func (p *Plugin) Destroy() {
	if p != nil && p.driver != nil {
		p.driver.Destroy()
		p.driver = nil
	}
}

// Issue runs the ACME order for the request's domains and finalizes it with the
// request's CSR, returning the issued certificate chain.
func (p *Plugin) Issue(ctx context.Context, req ca.IssueRequest) (ca.Certificate, error) {
	if len(req.DNSNames) == 0 {
		return ca.Certificate{}, fmt.Errorf("letsencrypt: at least one DNS name is required")
	}

	// req.TenantID travels with the order. It used to be dropped here, which
	// meant nothing downstream could scope a lookup to the tenant — fine while
	// no solver existed, and an AN-1 hole the moment one did.
	der, err := p.driver.IssueChain(ctx, acmekey.OrderRequest{
		TenantID: req.TenantID, DNSNames: req.DNSNames, CSR: req.CSR,
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return ca.Certificate{}, err
		}
		// ACME problem documents carry free-form detail and some gateways echo
		// account authorization, so the upstream error never reaches a caller.
		// But collapsing EVERY failure into one sentence left an operator with
		// no idea whether to fix DNS, fix CAA, or wait — so the classified
		// domain-validation failures are distinguished by a closed set of
		// phrases that name no provider, no record and no problem detail.
		return ca.Certificate{}, dvFailureOrGeneric(err)
	}

	chain := make([]byte, 0)
	for _, b := range der {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})...)
	}
	info, err := certinfo.Inspect(chain)
	if err != nil {
		secret.Wipe(chain)
		return ca.Certificate{}, errors.New("letsencrypt: upstream returned an invalid certificate chain")
	}
	return ca.Certificate{
		CertificatePEM: chain,
		Serial:         info.SerialNumber,
		NotAfter:       info.NotAfter,
		Issuer:         p.name,
	}, nil
}

var _ ca.Revoker = (*Plugin)(nil)

// Revoke revokes through the ACME authority (epic R2, RFC 8555 §7.6).
//
// ACME has no serial-based revocation: the request carries the certificate's
// DER, signed with the account key. So this needs the certificate itself, and
// says so when it does not have one rather than sending a request that cannot
// identify anything. An operator revoking a compromised key needs to know
// immediately that trstctl could not do it, not later.
func (p *Plugin) Revoke(ctx context.Context, req ca.RevokeRequest) error {
	if p == nil || p.driver == nil {
		return errors.New("letsencrypt: plugin is destroyed")
	}
	if len(req.CertificatePEM) == 0 {
		return fmt.Errorf("letsencrypt: %w: ACME identifies the certificate to revoke by its bytes, "+
			"and this request carries none — revocation by serial alone is not something the "+
			"protocol offers", ca.ErrRevocationUnsupported)
	}
	block, _ := pem.Decode(req.CertificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("letsencrypt: certificate material is not a PEM CERTIFICATE block")
	}
	return p.driver.RevokeChain(ctx, block.Bytes, req.ReasonCode)
}

// dvFailureOrGeneric maps a classified domain-validation failure to a closed
// phrase an operator can act on, and everything else to the generic message.
//
// The phrases name a category, never a value: no provider name, no record
// content, no ACME problem detail. What an operator needs is which of the four
// or five things to go and look at.
func dvFailureOrGeneric(err error) error {
	switch {
	case errors.Is(err, acme.ErrNoDNS01ProviderConfig):
		return newSafeACMEError("external_ca_dns01_unconfigured",
			"letsencrypt: no DNS-01 provider config covers the requested name; add a tenant DNS-01 provider config "+
				"(allow_upstream_dv) for its zone before issuing through this authority", err)
	case errors.Is(err, acmekey.ErrSolverNotConfigured):
		return errors.New("letsencrypt: this issuer has no domain-validation solver configured, " +
			"so it can only obtain certificates for identifiers the authority has already authorized")
	case errors.Is(err, acmekey.ErrNoSolvableChallenge):
		return errors.New("letsencrypt: the authority offered no challenge this deployment can solve")
	case strings.Contains(err.Error(), "acmekey: register:"):
		return newSafeACMEError("external_ca_account_failed", "letsencrypt: ACME account setup failed", err)
	case strings.Contains(err.Error(), "acmekey: authorize order:"):
		return newSafeACMEError("external_ca_order_failed", "letsencrypt: ACME order creation failed", err)
	case strings.Contains(err.Error(), "acmekey: finalize:"):
		return newSafeACMEError("external_ca_finalize_failed", "letsencrypt: ACME certificate finalization failed", err)
	default:
		return newSafeACMEError("external_ca_protocol_failed", "letsencrypt: upstream ACME issuance failed", err)
	}
}

// safeACMEError keeps the provider's arbitrary problem body out of logs and
// PostgreSQL while carrying one closed diagnostic class to the outbox. The raw
// cause remains unwrap-able for in-process control flow and is never rendered by
// Error. An untrusted provider therefore cannot smuggle a credential into the
// retained delivery ledger through its error text.
type safeACMEError struct {
	class string
	text  string
	cause error
}

func newSafeACMEError(class, text string, cause error) error {
	return &safeACMEError{class: class, text: text, cause: cause}
}

func (e *safeACMEError) Error() string             { return e.text }
func (e *safeACMEError) Unwrap() error             { return e.cause }
func (e *safeACMEError) SafeDeliveryClass() string { return e.class }
func (e *safeACMEError) Destroy() {
	var destroyer interface{ Destroy() }
	if errors.As(e.cause, &destroyer) {
		destroyer.Destroy()
	}
	e.cause = nil
}
