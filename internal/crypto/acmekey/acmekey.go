// SPDX-License-Identifier: MPL-2.0

// Package acmekey builds an ACME client with a fresh account key inside the AN-3
// crypto boundary (a subpackage of internal/crypto). The ACME account key is an
// ECDSA private key; constructing it and wiring it into the client here means the
// Let's Encrypt plugin never imports crypto/* and never names crypto.Signer.
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"golang.org/x/crypto/acme"
)

// NewClient returns an ACME client for the directory at directoryURL, with a
// freshly generated ECDSA P-256 account key.
func NewClient(directoryURL string) (*acme.Client, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &acme.Client{Key: key, DirectoryURL: directoryURL}, nil
}

// NewRSAClient returns an ACME client with a freshly generated RSA account key
// (RS256 JWS). The built-in ACME server verifies RSA account keys.
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

// NewDriver builds a Driver for the ACME directory at directoryURL with a fresh
// ECDSA account key and the given HTTP-01 solver (nil = a no-op solver, for
// pre-authorized orders).
func NewDriver(directoryURL string, solver ChallengeSolver) (*Driver, error) {
	client, err := NewClient(directoryURL)
	if err != nil {
		return nil, err
	}
	if solver == nil {
		solver = noopSolver{}
	}
	return &Driver{client: client, solver: solver}, nil
}

type noopSolver struct{}

func (noopSolver) Present(string, string, string) error { return nil }
func (noopSolver) Cleanup(string, string) error         { return nil }

// IssueChain registers the account, authorizes an order for dnsNames (solving any
// pending HTTP-01 challenges via the solver), finalizes it with csr, and returns
// the issued certificate chain as DER blocks (leaf first). The caller PEM-encodes
// the result; no acme.* type crosses this boundary.
func (d *Driver) IssueChain(ctx context.Context, dnsNames []string, csr []byte) ([][]byte, error) {
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
