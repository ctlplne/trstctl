package ca

import (
	"context"
	"time"

	cryptoca "trstctl.com/trstctl/internal/crypto/ca"
)

// defaultTTL is used when an issue request does not specify one.
const defaultTTL = 90 * 24 * time.Hour

// Builtin is the in-process built-in certificate authority — the reference CA on
// the CA interface. It signs through the internal/crypto/ca boundary; in
// production the same interface is satisfied by a signer-backed authority (AN-4).
type Builtin struct {
	name      string
	authority *cryptoca.Authority
}

var _ CA = (*Builtin)(nil)

// NewBuiltin creates a built-in CA with a fresh signing key and self-signed CA
// certificate.
func NewBuiltin(name string) (*Builtin, error) {
	authority, err := cryptoca.NewAuthority(name)
	if err != nil {
		return nil, err
	}
	return &Builtin{name: name, authority: authority}, nil
}

// Name identifies the authority.
func (b *Builtin) Name() string { return b.name }

// CertificatePEM returns the CA's own certificate (the trust anchor for its
// issued chains).
func (b *Builtin) CertificatePEM() []byte { return b.authority.CertificatePEM() }

// Issue signs the request's CSR.
func (b *Builtin) Issue(_ context.Context, req IssueRequest) (Certificate, error) {
	ttl := req.TTL
	if ttl <= 0 {
		ttl = defaultTTL
	}
	issued, err := b.authority.IssueFromCSR(req.CSR, ttl)
	if err != nil {
		return Certificate{}, err
	}
	return Certificate{
		CertificatePEM: issued.CertificatePEM,
		Serial:         issued.Serial,
		NotAfter:       issued.NotAfter,
		Issuer:         b.name,
	}, nil
}
