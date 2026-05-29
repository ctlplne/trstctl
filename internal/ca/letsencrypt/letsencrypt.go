// Package letsencrypt is the first CA plugin: an ACME (RFC 8555) certificate
// authority — Let's Encrypt or any ACME CA — implementing the ca.CA interface.
// It drives the order through golang.org/x/crypto/acme and finalizes with the
// caller's CSR. The ACME account key lives behind the crypto boundary
// (internal/crypto/acmekey), so this package holds no crypto/* import.
//
// On the platform it runs behind ca.IssuanceService, which gives it idempotency
// (AN-5, no double-mint on retry) and an outbox record (AN-6, observability); the
// signer custodies issuing keys (AN-4) — here the upstream CA holds them.
package letsencrypt

import (
	"context"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/acme"

	"certctl.io/certctl/internal/ca"
	"certctl.io/certctl/internal/crypto/acmekey"
	"certctl.io/certctl/internal/crypto/certinfo"
)

// ChallengeSolver provisions and removes the response for an ACME challenge (for
// example, serving an HTTP-01 token or publishing a DNS-01 record).
type ChallengeSolver interface {
	Present(domain, token, keyAuth string) error
	Cleanup(domain, token string) error
}

// noopSolver is used with pre-authorized orders (no challenge to fulfill).
type noopSolver struct{}

func (noopSolver) Present(string, string, string) error { return nil }
func (noopSolver) Cleanup(string, string) error         { return nil }

// Plugin is an ACME CA plugin.
type Plugin struct {
	name   string
	client *acme.Client
	solver ChallengeSolver
}

var _ ca.CA = (*Plugin)(nil)

// NewPlugin creates an ACME CA plugin named name, talking to the ACME directory
// at directoryURL, with a fresh account key. The default challenge solver is a
// no-op (for pre-authorized orders); use NewPluginWithSolver to provide one.
func NewPlugin(name, directoryURL string) (*Plugin, error) {
	return NewPluginWithSolver(name, directoryURL, noopSolver{})
}

// NewPluginWithSolver is NewPlugin with an explicit challenge solver.
func NewPluginWithSolver(name, directoryURL string, solver ChallengeSolver) (*Plugin, error) {
	client, err := acmekey.NewClient(directoryURL)
	if err != nil {
		return nil, err
	}
	return &Plugin{name: name, client: client, solver: solver}, nil
}

// Name identifies the authority.
func (p *Plugin) Name() string { return p.name }

// Issue runs the ACME order for the request's domains and finalizes it with the
// request's CSR, returning the issued certificate chain.
func (p *Plugin) Issue(ctx context.Context, req ca.IssueRequest) (ca.Certificate, error) {
	if len(req.DNSNames) == 0 {
		return ca.Certificate{}, fmt.Errorf("letsencrypt: at least one DNS name is required")
	}
	if _, err := p.client.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil {
		return ca.Certificate{}, fmt.Errorf("letsencrypt: register: %w", err)
	}

	order, err := p.client.AuthorizeOrder(ctx, acme.DomainIDs(req.DNSNames...))
	if err != nil {
		return ca.Certificate{}, fmt.Errorf("letsencrypt: authorize order: %w", err)
	}
	if order.Status != acme.StatusReady {
		if err := p.fulfill(ctx, order); err != nil {
			return ca.Certificate{}, err
		}
		if order, err = p.client.WaitOrder(ctx, order.URI); err != nil {
			return ca.Certificate{}, fmt.Errorf("letsencrypt: wait order: %w", err)
		}
	}

	der, _, err := p.client.CreateOrderCert(ctx, order.FinalizeURL, req.CSR, true)
	if err != nil {
		return ca.Certificate{}, fmt.Errorf("letsencrypt: finalize: %w", err)
	}

	chain := make([]byte, 0)
	for _, b := range der {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})...)
	}
	info, err := certinfo.Inspect(chain)
	if err != nil {
		return ca.Certificate{}, fmt.Errorf("letsencrypt: parse issued cert: %w", err)
	}
	return ca.Certificate{
		CertificatePEM: chain,
		Serial:         info.SerialNumber,
		NotAfter:       info.NotAfter,
		Issuer:         p.name,
	}, nil
}

// fulfill solves the pending authorizations of an order via the configured
// challenge solver (HTTP-01), then accepts each challenge.
func (p *Plugin) fulfill(ctx context.Context, order *acme.Order) error {
	for _, authzURL := range order.AuthzURLs {
		authz, err := p.client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return fmt.Errorf("letsencrypt: get authorization: %w", err)
		}
		if authz.Status == acme.StatusValid {
			continue
		}
		chal := httpChallenge(authz)
		if chal == nil {
			return fmt.Errorf("letsencrypt: authorization %s offers no http-01 challenge", authz.Identifier.Value)
		}
		response, err := p.client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return err
		}
		if err := p.solver.Present(authz.Identifier.Value, chal.Token, response); err != nil {
			return fmt.Errorf("letsencrypt: present challenge: %w", err)
		}
		if _, err := p.client.Accept(ctx, chal); err != nil {
			return fmt.Errorf("letsencrypt: accept challenge: %w", err)
		}
		if _, err := p.client.WaitAuthorization(ctx, authzURL); err != nil {
			return fmt.Errorf("letsencrypt: wait authorization: %w", err)
		}
		_ = p.solver.Cleanup(authz.Identifier.Value, chal.Token)
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
