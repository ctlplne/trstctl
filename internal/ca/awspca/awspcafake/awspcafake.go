// Package awspcafake is a faithful in-process double of the AWS Private CA
// (acm-pca) API the plugin uses, enough to exercise the plugin end-to-end in a
// Linux CI where the AWS SDK / SigV4 transport cannot run. It implements
// awspca.API with the service's semantics — IssueCertificate returns a
// certificate ARN, GetCertificate raises RequestInProgress until the certificate
// is ready then returns the leaf and chain, and an unknown CA ARN is rejected —
// and signs submitted CSRs with a local software authority via the crypto
// boundary, so it holds no crypto/* itself.
package awspcafake

import (
	"context"
	"encoding/pem"
	"fmt"
	"strconv"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/ca/awspca"
	cryptoca "trstctl.com/trstctl/internal/crypto/ca"
)

// caArn is the certificate-authority ARN this double recognizes.
const caArn = "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/11111111-2222-3333-4444-555555555555"

// API is an in-process acm-pca double backed by a software CA.
type API struct {
	authority *cryptoca.Authority

	mu           sync.Mutex
	certs        map[string][]byte // certificate ARN -> chain PEM
	getCount     map[string]int
	seq          int
	pendingPolls int
}

var _ awspca.API = (*API)(nil)

// NewAPI starts a fake acm-pca backed by a fresh software CA. By default
// certificates are ready on the first GetCertificate call.
func NewAPI() (*API, error) {
	authority, err := cryptoca.NewAuthority("AWS Private CA Test Root")
	if err != nil {
		return nil, err
	}
	return &API{authority: authority, certs: map[string][]byte{}, getCount: map[string]int{}}, nil
}

// CAArn is the certificate-authority ARN the double recognizes.
func (a *API) CAArn() string { return caArn }

// SetPendingPolls makes the first n GetCertificate calls for each certificate
// report RequestInProgress before the chain is returned.
func (a *API) SetPendingPolls(n int) {
	a.mu.Lock()
	a.pendingPolls = n
	a.mu.Unlock()
}

// IssueCertificate implements awspca.API.
func (a *API) IssueCertificate(_ context.Context, in awspca.IssueCertificateInput) (awspca.IssueCertificateOutput, error) {
	if in.CertificateAuthorityArn != caArn {
		return awspca.IssueCertificateOutput{}, fmt.Errorf("ResourceNotFoundException: certificate authority %q not found", in.CertificateAuthorityArn)
	}
	block, _ := pem.Decode(in.Csr)
	if block == nil {
		return awspca.IssueCertificateOutput{}, fmt.Errorf("MalformedCSRException: could not parse CSR")
	}
	issued, err := a.authority.IssueFromCSR(block.Bytes, validityToTTL(in.Validity))
	if err != nil {
		return awspca.IssueCertificateOutput{}, fmt.Errorf("RequestFailedException: %w", err)
	}
	a.mu.Lock()
	a.seq++
	arn := caArn + "/certificate/" + strconv.Itoa(a.seq)
	a.certs[arn] = issued.CertificatePEM
	a.getCount[arn] = 0
	a.mu.Unlock()
	return awspca.IssueCertificateOutput{CertificateArn: arn}, nil
}

// GetCertificate implements awspca.API.
func (a *API) GetCertificate(_ context.Context, in awspca.GetCertificateInput) (awspca.GetCertificateOutput, error) {
	a.mu.Lock()
	chain, ok := a.certs[in.CertificateArn]
	a.getCount[in.CertificateArn]++
	pending := a.getCount[in.CertificateArn] <= a.pendingPolls
	a.mu.Unlock()
	if !ok {
		return awspca.GetCertificateOutput{}, fmt.Errorf("ResourceNotFoundException: certificate %q not found", in.CertificateArn)
	}
	if pending {
		return awspca.GetCertificateOutput{}, awspca.ErrRequestInProgress
	}
	leaf, rest := splitChain(chain)
	return awspca.GetCertificateOutput{Certificate: leaf, CertificateChain: rest}, nil
}

func validityToTTL(v awspca.Validity) time.Duration {
	if v.Value <= 0 {
		return 365 * 24 * time.Hour
	}
	switch v.Type {
	case "MONTHS":
		return time.Duration(v.Value) * 30 * 24 * time.Hour
	case "YEARS":
		return time.Duration(v.Value) * 365 * 24 * time.Hour
	default: // DAYS (and anything else, conservatively)
		return time.Duration(v.Value) * 24 * time.Hour
	}
}

// splitChain returns the first CERTIFICATE block (leaf) and the remaining blocks
// (the chain to the root), each as PEM text.
func splitChain(pemBytes []byte) (leaf, chain string) {
	rest := pemBytes
	first := true
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		enc := string(pem.EncodeToMemory(block))
		if first {
			leaf = enc
			first = false
		} else {
			chain += enc
		}
		rest = r
	}
	return leaf, chain
}
