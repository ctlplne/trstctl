// SPDX-License-Identifier: BUSL-1.1

// Package awspca is the AWS Private CA (acm-pca) CA plugin (F4, sprint S4.12),
// built from the CA-plugin template (internal/ca/catemplate): it implements only
// the CA-specific Backend and the template contributes the rest.
//
// AWS Private CA issues asynchronously over a two-call flow: IssueCertificate
// submits the CSR and returns a certificate ARN, then GetCertificate is polled —
// it raises RequestInProgressException until the certificate is ready, then
// returns the leaf and chain (PEM). HTTPAPI is the production AWS JSON 1.1
// transport and signs every call with SigV4/IAM credentials. The API seam keeps
// issue/poll semantics testable with the faithful in-process double in
// internal/ca/awspca/awspcafake.
//
// The package holds no crypto/* (AN-3) and custodies no signing key — AWS does —
// so AN-4 is not implicated; on the platform it runs behind ca.IssuanceService
// for idempotency (AN-5) and the outbox (AN-6).
package awspca

import (
	"context"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
	"trstctl.com/trstctl/internal/crypto"
)

// ErrRequestInProgress mirrors acm-pca's RequestInProgressException: the
// certificate is still being issued and is not yet available from GetCertificate.
var ErrRequestInProgress = errors.New("awspca: request in progress")

// Validity mirrors the acm-pca Validity object. Type is one of DAYS, MONTHS,
// YEARS, ABSOLUTE, END_DATE.
type Validity struct {
	Value int64
	Type  string
}

// IssueCertificateInput mirrors the acm-pca IssueCertificate request.
type IssueCertificateInput struct {
	CertificateAuthorityArn string
	Csr                     []byte // PEM-encoded CSR
	SigningAlgorithm        string
	Validity                Validity
	IdempotencyToken        string
}

// IssueCertificateOutput mirrors the acm-pca IssueCertificate response.
type IssueCertificateOutput struct {
	CertificateArn string
}

// GetCertificateInput mirrors the acm-pca GetCertificate request.
type GetCertificateInput struct {
	CertificateAuthorityArn string
	CertificateArn          string
}

// GetCertificateOutput mirrors the acm-pca GetCertificate response.
type GetCertificateOutput struct {
	Certificate      string // PEM leaf
	CertificateChain string // PEM chain to the root
}

// API is the subset of AWS Private CA used by the plugin. HTTPAPI is the
// production SigV4 implementation; tests may use an in-process double.
type API interface {
	IssueCertificate(ctx context.Context, in IssueCertificateInput) (IssueCertificateOutput, error)
	GetCertificate(ctx context.Context, in GetCertificateInput) (GetCertificateOutput, error)
}

const (
	defaultSigningAlgorithm = "SHA256WITHRSA"
	defaultValidityDays     = 365
	defaultPoll             = 2 * time.Second
	maxPolls                = 60
)

// Config holds the acm-pca target and issuance settings.
type Config struct {
	Name                    string
	CertificateAuthorityArn string
	SigningAlgorithm        string // default SHA256WITHRSA
}

// backend drives the acm-pca issue→poll-get flow over the API seam. It is the
// only CA-specific code; the template supplies the ca.CA behavior.
type backend struct {
	cfg  Config
	api  API
	poll time.Duration
}

// Option configures the plugin.
type Option func(*backend)

// WithPollInterval sets the delay between GetCertificate polls while issuance is
// in progress.
func WithPollInterval(d time.Duration) Option {
	return func(b *backend) {
		if d > 0 {
			b.poll = d
		}
	}
}

// New builds the AWS Private CA plugin over api. The returned *catemplate.Plugin
// is a ca.CA.
func New(cfg Config, api API, opts ...Option) *catemplate.Plugin {
	b := &backend{cfg: cfg, api: api, poll: defaultPoll}
	for _, o := range opts {
		o(b)
	}
	return catemplate.New(b)
}

// CAName identifies the authority.
func (b *backend) CAName() string { return b.cfg.Name }

// Destroy releases credentials retained by a short-lived production API.
func (b *backend) Destroy() {
	if d, ok := b.api.(interface{ Destroy() }); ok {
		d.Destroy()
	}
}

// Issue submits the CSR with IssueCertificate and polls GetCertificate for the
// issued chain.
func (b *backend) Issue(ctx context.Context, req ca.IssueRequest) ([]byte, error) {
	if len(req.DNSNames) == 0 {
		return nil, fmt.Errorf("awspca: at least one DNS name is required")
	}
	days := int64(req.TTL / (24 * time.Hour))
	if days < 1 {
		days = defaultValidityDays
	}
	token := req.ProviderIdempotencyKey
	if token == "" {
		var err error
		token, err = idempotencyToken()
		if err != nil {
			return nil, err
		}
	}
	alg := b.cfg.SigningAlgorithm
	if alg == "" {
		alg = defaultSigningAlgorithm
	}
	out, err := b.api.IssueCertificate(ctx, IssueCertificateInput{
		CertificateAuthorityArn: b.cfg.CertificateAuthorityArn,
		Csr:                     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: req.CSR}),
		SigningAlgorithm:        alg,
		Validity:                Validity{Value: days, Type: "DAYS"},
		IdempotencyToken:        token,
	})
	if err != nil {
		return nil, fmt.Errorf("awspca: issue certificate: %w", err)
	}
	return b.awaitCertificate(ctx, out.CertificateArn)
}

// awaitCertificate polls GetCertificate until the certificate is ready, then
// assembles the leaf and chain into a PEM chain.
func (b *backend) awaitCertificate(ctx context.Context, certArn string) ([]byte, error) {
	for polls := 0; ; polls++ {
		got, err := b.api.GetCertificate(ctx, GetCertificateInput{
			CertificateAuthorityArn: b.cfg.CertificateAuthorityArn,
			CertificateArn:          certArn,
		})
		if err == nil {
			if got.Certificate == "" {
				return nil, fmt.Errorf("awspca: certificate %s returned empty", certArn)
			}
			return assembleChain(got.Certificate, got.CertificateChain), nil
		}
		if !errors.Is(err, ErrRequestInProgress) {
			return nil, fmt.Errorf("awspca: get certificate: %w", err)
		}
		if polls >= maxPolls {
			return nil, fmt.Errorf("awspca: certificate %s still in progress after %d polls", certArn, polls)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(b.poll):
		}
	}
}

// assembleChain concatenates the leaf and chain PEM, leaf first.
func assembleChain(cert, chain string) []byte {
	var out []byte
	for _, p := range []string{cert, chain} {
		if p == "" {
			continue
		}
		out = append(out, []byte(p)...)
		if !strings.HasSuffix(p, "\n") {
			out = append(out, '\n')
		}
	}
	return out
}

// idempotencyToken returns a random acm-pca idempotency token. The platform's
// IssuanceService is the authoritative idempotency guard (AN-5); this token is
// acm-pca's own five-minute dedupe window.
func idempotencyToken() (string, error) {
	b, err := crypto.RandomBytes(16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
