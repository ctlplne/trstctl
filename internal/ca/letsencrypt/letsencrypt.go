// Package letsencrypt is the first CA plugin: an ACME (RFC 8555) certificate
// authority — Let's Encrypt or any ACME CA — implementing the ca.CA interface.
// It drives the order through the crypto boundary's acmekey.Driver (which wraps
// golang.org/x/crypto/acme) and finalizes with the caller's CSR. The ACME account
// key and the whole ACME/crypto dependency live behind the crypto boundary
// (internal/crypto/acmekey), so this package holds no crypto/* import and no
// third-party-crypto import (AN-3, CRYPTO-002).
//
// On the platform it runs behind ca.IssuanceService, which gives it idempotency
// (AN-5, no double-mint on retry) and an outbox record (AN-6, observability); the
// signer custodies issuing keys (AN-4) — here the upstream CA holds them.
package letsencrypt

import (
	"context"
	"encoding/pem"
	"fmt"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// ChallengeSolver provisions and removes the response for an ACME challenge (for
// example, serving an HTTP-01 token or publishing a DNS-01 record). It is the
// neutral solver seam from the crypto boundary, so this package names no acme.*
// type.
type ChallengeSolver = acmekey.ChallengeSolver

// Plugin is an ACME CA plugin.
type Plugin struct {
	name   string
	driver *acmekey.Driver
}

var _ ca.CA = (*Plugin)(nil)

// NewPlugin creates an ACME CA plugin named name, talking to the ACME directory
// at directoryURL, with a fresh account key. The default challenge solver is a
// no-op (for pre-authorized orders); use NewPluginWithSolver to provide one.
func NewPlugin(name, directoryURL string) (*Plugin, error) {
	return NewPluginWithSolver(name, directoryURL, nil)
}

// NewPluginWithSolver is NewPlugin with an explicit challenge solver.
func NewPluginWithSolver(name, directoryURL string, solver ChallengeSolver) (*Plugin, error) {
	driver, err := acmekey.NewDriver(directoryURL, solver)
	if err != nil {
		return nil, err
	}
	return &Plugin{name: name, driver: driver}, nil
}

// Name identifies the authority.
func (p *Plugin) Name() string { return p.name }

// Issue runs the ACME order for the request's domains and finalizes it with the
// request's CSR, returning the issued certificate chain.
func (p *Plugin) Issue(ctx context.Context, req ca.IssueRequest) (ca.Certificate, error) {
	if len(req.DNSNames) == 0 {
		return ca.Certificate{}, fmt.Errorf("letsencrypt: at least one DNS name is required")
	}

	der, err := p.driver.IssueChain(ctx, req.DNSNames, req.CSR)
	if err != nil {
		return ca.Certificate{}, fmt.Errorf("letsencrypt: %w", err)
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
