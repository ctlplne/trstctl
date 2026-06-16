// Package example is the reference CA plugin generated from the CA-plugin
// template (internal/ca/catemplate). It is the scaffold a new CA copies: to add
// an authority, copy this package, rename it, and reimplement backend.Issue to
// call that CA's API — everything else (the ca.CA interface, request validation,
// chain parsing, issuer labelling, error wrapping, and riding the idempotency
// and outbox rails through ca.IssuanceService) comes from the template.
//
// This example's backend signs against a local in-process software authority — a
// faithful CA test double — so it builds and passes the conformance suite with
// no external service, the way each real CA plugin (S4.7–S4.14) will against its
// own CA or test double.
package example

import (
	"context"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
	cryptoca "trstctl.com/trstctl/internal/crypto/ca"
)

// defaultTTL is requested when a request does not specify a lifetime.
const defaultTTL = 90 * 24 * time.Hour

// backend is the CA-specific seam: the only code a new plugin writes. A real
// plugin would hold an API client and call its CA here; this one holds a local
// software authority.
type backend struct {
	name      string
	authority *cryptoca.Authority
}

// CAName identifies the authority.
func (b *backend) CAName() string { return b.name }

// Issue submits the CSR to the (here, local) authority and returns the chain.
func (b *backend) Issue(_ context.Context, req ca.IssueRequest) ([]byte, error) {
	ttl := req.TTL
	if ttl <= 0 {
		ttl = defaultTTL
	}
	issued, err := b.authority.IssueFromCSR(req.CSR, ttl)
	if err != nil {
		return nil, err
	}
	return issued.CertificatePEM, nil
}

// New builds the example CA plugin: a fresh local authority wrapped by the
// template. The returned *catemplate.Plugin is a ca.CA.
func New(name string) (*catemplate.Plugin, error) {
	authority, err := cryptoca.NewAuthority(name)
	if err != nil {
		return nil, err
	}
	return catemplate.New(&backend{name: name, authority: authority}), nil
}
