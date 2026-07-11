// SPDX-License-Identifier: MPL-2.0

// Package gcpcas is the Google Cloud Certificate Authority Service (CAS) CA
// plugin (F4, sprint S4.13), built from the CA-plugin template
// (internal/ca/catemplate): it implements only the CA-specific Backend and the
// template contributes the rest.
//
// Unlike AWS Private CA's asynchronous flow, CAS issues synchronously: a single
// CreateCertificate call on a CA pool (projects/{p}/locations/{l}/caPools/{pool})
// with the CSR and a lifetime returns the issued certificate with its leaf
// (pemCertificate) and chain (pemCertificateChain) directly — no polling. That
// HTTPAPI is the production CAS v1 REST/OAuth transport; the API seam also
// supports the faithful in-process double in internal/ca/gcpcas/gcpcasfake.
//
// The package holds no crypto/* (AN-3) and custodies no signing key — GCP does —
// so AN-4 is not implicated; on the platform it runs behind ca.IssuanceService
// for idempotency (AN-5) and the outbox (AN-6).
package gcpcas

import (
	"context"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
	"trstctl.com/trstctl/internal/crypto"
)

// CreateCertificateInput mirrors the CAS caPools.certificates.create request.
type CreateCertificateInput struct {
	Parent        string // projects/{p}/locations/{l}/caPools/{pool}
	CertificateID string
	PemCSR        []byte
	Lifetime      time.Duration
	RequestID     string // idempotency
}

// Certificate mirrors the CAS Certificate resource (the create response).
type Certificate struct {
	Name                string
	PemCertificate      string   // leaf, PEM
	PemCertificateChain []string // issuing chain, PEM
}

// API is the subset of CAS used by the plugin. HTTPAPI is the production OAuth2
// implementation. CAS issues synchronously, so CreateCertificate returns the
// issued certificate directly.
type API interface {
	CreateCertificate(ctx context.Context, in CreateCertificateInput) (Certificate, error)
}

const defaultValidity = 90 * 24 * time.Hour

// Config holds the CAS target.
type Config struct {
	Name   string
	CaPool string // projects/{p}/locations/{l}/caPools/{pool}
}

// backend drives CAS CreateCertificate over the API seam. It is the only
// CA-specific code; the template supplies the ca.CA behaviour.
type backend struct {
	cfg Config
	api API
}

// New builds the GCP CAS plugin over api. The returned *catemplate.Plugin is a
// ca.CA.
func New(cfg Config, api API) *catemplate.Plugin {
	return catemplate.New(&backend{cfg: cfg, api: api})
}

// CAName identifies the authority.
func (b *backend) CAName() string { return b.cfg.Name }

// Destroy releases credentials retained by a short-lived production API.
func (b *backend) Destroy() {
	if d, ok := b.api.(interface{ Destroy() }); ok {
		d.Destroy()
	}
}

// Issue creates a certificate on the CA pool and assembles the returned leaf and
// chain into a PEM chain.
func (b *backend) Issue(ctx context.Context, req ca.IssueRequest) ([]byte, error) {
	if len(req.DNSNames) == 0 {
		return nil, fmt.Errorf("gcpcas: at least one DNS name is required")
	}
	lifetime := req.TTL
	if lifetime <= 0 {
		lifetime = defaultValidity
	}
	certID, requestID, err := providerIDs(req.ProviderIdempotencyKey)
	if err != nil {
		return nil, err
	}
	out, err := b.api.CreateCertificate(ctx, CreateCertificateInput{
		Parent:        b.cfg.CaPool,
		CertificateID: "trstctl-" + certID,
		PemCSR:        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: req.CSR}),
		Lifetime:      lifetime,
		RequestID:     requestID,
	})
	if err != nil {
		return nil, fmt.Errorf("gcpcas: create certificate: %w", err)
	}
	if out.PemCertificate == "" {
		return nil, fmt.Errorf("gcpcas: create certificate returned no certificate")
	}
	return assembleChain(out.PemCertificate, out.PemCertificateChain), nil
}

// providerIDs maps the platform's stable provider idempotency key to both CAS
// request identifiers. A replay therefore addresses the same Certificate
// resource and the same requestId instead of minting a second certificate.
func providerIDs(providerKey string) (certificateID, requestID string, err error) {
	key := strings.ToLower(strings.TrimSpace(providerKey))
	if len(key) >= 32 {
		key = key[:32]
		return "trstctl-" + key[:24], key[:8] + "-" + key[8:12] + "-" + key[12:16] + "-" + key[16:20] + "-" + key[20:32], nil
	}
	certRandom, err := randomID()
	if err != nil {
		return "", "", err
	}
	requestRandom, err := randomID()
	if err != nil {
		return "", "", err
	}
	return "trstctl-" + certRandom, requestRandom[:8] + "-" + requestRandom[8:12] + "-" + requestRandom[12:16] + "-" + requestRandom[16:20] + "-" + requestRandom[20:32], nil
}

// assembleChain concatenates the leaf and chain PEM, leaf first.
func assembleChain(leaf string, chain []string) []byte {
	var out []byte
	appendPEM := func(p string) {
		if p == "" {
			return
		}
		out = append(out, []byte(p)...)
		if !strings.HasSuffix(p, "\n") {
			out = append(out, '\n')
		}
	}
	appendPEM(leaf)
	for _, c := range chain {
		appendPEM(c)
	}
	return out
}

// randomID returns a random hex id (for the CAS certificate id and request id).
// The platform's IssuanceService is the authoritative idempotency guard (AN-5).
func randomID() (string, error) {
	b, err := crypto.RandomBytes(16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
