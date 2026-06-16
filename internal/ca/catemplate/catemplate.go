// Package catemplate is the reusable CA-plugin template (F4). It extracts the
// shape shared by every CA plugin — the one the Let's Encrypt plugin (S4.3)
// established — so each remaining authority is a small, near-identical change:
// implement one CA-specific seam and wrap it.
//
// A CA plugin differs from every other only in how it asks its upstream
// authority to sign a CSR. Everything else — implementing the ca.CA interface,
// validating the request, parsing the issued chain, extracting the serial and
// expiry, labelling the issuer, wrapping errors — is identical, and lives here.
// A new plugin therefore implements just Backend (see the example plugin in
// internal/ca/example and README.md) and wraps it with New; it then rides the
// same issuance rails (idempotency AN-5, outbox AN-6) through ca.IssuanceService
// as any other CA, and self-validates with Conformance.
package catemplate

import (
	"context"
	"fmt"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// Backend is the CA-specific seam a plugin fills in: it submits a CSR to its
// upstream certificate authority and returns the issued chain (leaf first),
// PEM-encoded. It is the only code a new CA plugin writes.
type Backend interface {
	// CAName identifies the authority (for example "digicert"); it labels the
	// issued certificate and appears in events.
	CAName() string
	// Issue submits req.CSR to the upstream CA, authorizing req.DNSNames and
	// requesting req.TTL where the CA honours it, and returns the chain PEM.
	Issue(ctx context.Context, req ca.IssueRequest) (chainPEM []byte, err error)
}

// Plugin adapts a Backend to the ca.CA interface, contributing all the shared
// logic so the Backend stays minimal.
type Plugin struct {
	backend Backend
}

var _ ca.CA = (*Plugin)(nil)

// New wraps a Backend as a CA plugin.
func New(backend Backend) *Plugin { return &Plugin{backend: backend} }

// Name identifies the authority.
func (p *Plugin) Name() string { return p.backend.CAName() }

// Issue validates the request, delegates the upstream call to the Backend,
// parses the issued chain, and returns the certificate with its serial, expiry,
// and issuer label.
func (p *Plugin) Issue(ctx context.Context, req ca.IssueRequest) (ca.Certificate, error) {
	name := p.backend.CAName()
	if len(req.CSR) == 0 {
		return ca.Certificate{}, fmt.Errorf("catemplate: %s: issue request has no CSR", name)
	}
	chain, err := p.backend.Issue(ctx, req)
	if err != nil {
		return ca.Certificate{}, fmt.Errorf("catemplate: %s: issue: %w", name, err)
	}
	if len(chain) == 0 {
		return ca.Certificate{}, fmt.Errorf("catemplate: %s: upstream returned an empty chain", name)
	}
	info, err := certinfo.Inspect(chain)
	if err != nil {
		return ca.Certificate{}, fmt.Errorf("catemplate: %s: parse issued chain: %w", name, err)
	}
	return ca.Certificate{
		CertificatePEM: chain,
		Serial:         info.SerialNumber,
		NotAfter:       info.NotAfter,
		Issuer:         name,
	}, nil
}
