// Package azurekv is the Azure Key Vault CA plugin (F4, sprint S4.14) — the last
// of the cloud CAs — built from the CA-plugin template (internal/ca/catemplate):
// it implements only the CA-specific Backend and the template contributes the
// rest.
//
// Key Vault issues a certificate asynchronously: a create call on a named
// certificate (with an x509 policy: subject and SANs) starts a CertificateOperation
// whose status moves inProgress -> completed; the operation is polled, then the
// certificate is fetched (its leaf is the base64-DER `cer`, followed by the
// issuing chain). That API is reached over HTTPS with Entra ID (AAD) bearer auth
// via the Azure SDK, which cannot run in a Linux CI, so the plugin drives the Key
// Vault create -> poll-operation -> get *semantics* over the azurekv.API seam,
// with a faithful in-process double for CI (internal/ca/azurekv/azurekvfake). The
// production Azure-SDK transport is the integration follow-up.
//
// The package holds no crypto/* (AN-3) and custodies no signing key — Key Vault
// does (it is key-custodial) — so AN-4 is not implicated; on the platform it runs
// behind ca.IssuanceService for idempotency (AN-5) and the outbox (AN-6).
package azurekv

import (
	"context"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
	"trstctl.com/trstctl/internal/crypto"
)

// CertificateOperation statuses (Key Vault CertificateOperation.status).
const (
	StatusInProgress = "inProgress"
	StatusCompleted  = "completed"
	StatusFailed     = "failed"
)

// CreateCertificateInput mirrors a Key Vault create-certificate request: a named
// certificate with an x509 policy. Csr carries trstctl's CSR (supplied on the
// Key Vault merge path).
type CreateCertificateInput struct {
	VaultBaseURL    string
	CertificateName string
	Subject         string
	DNSNames        []string
	Csr             []byte // PEM
	Lifetime        time.Duration
}

// CertificateOperation mirrors the Key Vault CertificateOperation.
type CertificateOperation struct {
	Status string
	Error  string
}

// Certificate mirrors the issued Key Vault certificate: the leaf (`cer`, DER) and
// its issuing chain (DER).
type Certificate struct {
	Cer   []byte
	Chain [][]byte
}

// API is the subset of the Key Vault certificates API the plugin uses. The
// production implementation is the Azure SDK (AAD auth); CI uses an in-process
// double. The certificate operation is inProgress until issuance completes.
type API interface {
	CreateCertificate(ctx context.Context, in CreateCertificateInput) (CertificateOperation, error)
	GetCertificateOperation(ctx context.Context, vaultBaseURL, certName string) (CertificateOperation, error)
	GetCertificate(ctx context.Context, vaultBaseURL, certName string) (Certificate, error)
}

const (
	defaultValidity = 90 * 24 * time.Hour
	defaultPoll     = 2 * time.Second
	maxPolls        = 60
)

// Config holds the Key Vault target.
type Config struct {
	Name              string
	VaultBaseURL      string // https://{vault}.vault.azure.net
	CertificatePrefix string // name prefix for created certificates (default "trstctl")
}

// backend drives the Key Vault create->poll->get flow over the API seam. It is
// the only CA-specific code; the template supplies the ca.CA behaviour.
type backend struct {
	cfg  Config
	api  API
	poll time.Duration
}

// Option configures the plugin.
type Option func(*backend)

// WithPollInterval sets the delay between certificate-operation polls.
func WithPollInterval(d time.Duration) Option {
	return func(b *backend) {
		if d > 0 {
			b.poll = d
		}
	}
}

// New builds the Azure Key Vault plugin over api. The returned *catemplate.Plugin
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

// Issue creates a Key Vault certificate, polls its operation to completion, and
// fetches the issued certificate.
func (b *backend) Issue(ctx context.Context, req ca.IssueRequest) ([]byte, error) {
	if len(req.DNSNames) == 0 {
		return nil, fmt.Errorf("azurekv: at least one DNS name is required")
	}
	lifetime := req.TTL
	if lifetime <= 0 {
		lifetime = defaultValidity
	}
	name, err := b.certificateName()
	if err != nil {
		return nil, err
	}
	op, err := b.api.CreateCertificate(ctx, CreateCertificateInput{
		VaultBaseURL:    b.cfg.VaultBaseURL,
		CertificateName: name,
		Subject:         "CN=" + req.DNSNames[0],
		DNSNames:        req.DNSNames,
		Csr:             pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: req.CSR}),
		Lifetime:        lifetime,
	})
	if err != nil {
		return nil, fmt.Errorf("azurekv: create certificate: %w", err)
	}
	if err := b.awaitOperation(ctx, name, op); err != nil {
		return nil, err
	}
	cert, err := b.api.GetCertificate(ctx, b.cfg.VaultBaseURL, name)
	if err != nil {
		return nil, fmt.Errorf("azurekv: get certificate: %w", err)
	}
	return assembleChain(cert)
}

// awaitOperation polls the certificate operation until it completes.
func (b *backend) awaitOperation(ctx context.Context, name string, op CertificateOperation) error {
	for polls := 0; ; polls++ {
		switch op.Status {
		case StatusCompleted:
			return nil
		case StatusFailed:
			msg := op.Error
			if msg == "" {
				msg = "certificate operation failed"
			}
			return fmt.Errorf("azurekv: certificate %s: %s", name, msg)
		case StatusInProgress:
			if polls >= maxPolls {
				return fmt.Errorf("azurekv: certificate %s still in progress after %d polls", name, polls)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(b.poll):
			}
			next, err := b.api.GetCertificateOperation(ctx, b.cfg.VaultBaseURL, name)
			if err != nil {
				return fmt.Errorf("azurekv: get certificate operation: %w", err)
			}
			op = next
		default:
			return fmt.Errorf("azurekv: certificate %s has unexpected operation status %q", name, op.Status)
		}
	}
}

// assembleChain PEM-encodes the leaf and chain DER into a leaf-first PEM chain.
func assembleChain(cert Certificate) ([]byte, error) {
	if len(cert.Cer) == 0 {
		return nil, fmt.Errorf("azurekv: certificate has no leaf")
	}
	var out []byte
	for _, der := range append([][]byte{cert.Cer}, cert.Chain...) {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out, nil
}

// certificateName builds a unique Key Vault certificate name. The platform's
// IssuanceService is the authoritative idempotency guard (AN-5).
func (b *backend) certificateName() (string, error) {
	prefix := b.cfg.CertificatePrefix
	if prefix == "" {
		prefix = "trstctl"
	}
	r, err := crypto.RandomBytes(12)
	if err != nil {
		return "", err
	}
	return prefix + "-" + hex.EncodeToString(r), nil
}
