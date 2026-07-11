// SPDX-License-Identifier: MPL-2.0

// Package letsencrypt is the first CA plugin: an ACME (RFC 8555) certificate
// authority — Let's Encrypt or any ACME CA — implementing the ca.CA interface.
// It drives the order through the crypto boundary's acmekey.Driver (which wraps
// golang.org/x/crypto/acme) and finalizes with the caller's CSR. The ACME account
// JWS adapter and the whole ACME/crypto dependency live behind the crypto
// boundary (internal/crypto/acmekey). The shipped constructor backs that adapter
// with the isolated signing process, so this package holds neither account-key
// private material nor crypto/* imports (AN-3/AN-4/AN-8, CRYPTO-002).
//
// On the platform it runs behind ca.IssuanceService, which gives it idempotency
// (AN-5, no double-mint on retry) and an outbox record (AN-6, observability); the
// signer custodies the ACME account key (AN-4), while the upstream CA signs the
// requested certificate.
package letsencrypt

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/acmekey"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Plugin is an ACME CA plugin.
type Plugin struct {
	name   string
	driver *acmekey.Driver
}

var _ ca.CA = (*Plugin)(nil)

// NewPluginWithRemoteAccountSigner is the production constructor. The ACME
// protocol still runs through x/crypto/acme, but the account JWS key is an
// opaque digest signer backed by the isolated signing process (AN-4/AN-8).
func NewPluginWithRemoteAccountSigner(name, directoryURL string, client *http.Client, signer crypto.DigestSigner) (*Plugin, error) {
	driver, err := acmekey.NewDriverWithDigestSigner(directoryURL, nil, client, signer)
	if err != nil {
		return nil, err
	}
	return &Plugin{name: name, driver: driver}, nil
}

// Name identifies the authority.
func (p *Plugin) Name() string { return p.name }

// Destroy releases the ACME client. Local/test constructors also zero their
// process-local account scalar; the shipped remote constructor only drops its
// public-key/transport adapter because signer custody remains out of process.
func (p *Plugin) Destroy() {
	if p != nil && p.driver != nil {
		p.driver.Destroy()
		p.driver = nil
	}
}

// Issue runs the ACME order for the request's domains and finalizes it with the
// request's CSR, returning the issued certificate chain.
func (p *Plugin) Issue(ctx context.Context, req ca.IssueRequest) (ca.Certificate, error) {
	if len(req.DNSNames) == 0 {
		return ca.Certificate{}, fmt.Errorf("letsencrypt: at least one DNS name is required")
	}

	der, err := p.driver.IssueChain(ctx, req.DNSNames, req.CSR)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return ca.Certificate{}, err
		}
		// ACME problem documents contain free-form detail fields and some gateways
		// echo account authorization. Keep the internal error out of every caller,
		// journal, and log path.
		return ca.Certificate{}, errors.New("letsencrypt: upstream ACME issuance failed")
	}

	chain := make([]byte, 0)
	for _, b := range der {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})...)
	}
	info, err := certinfo.Inspect(chain)
	if err != nil {
		secret.Wipe(chain)
		return ca.Certificate{}, errors.New("letsencrypt: upstream returned an invalid certificate chain")
	}
	return ca.Certificate{
		CertificatePEM: chain,
		Serial:         info.SerialNumber,
		NotAfter:       info.NotAfter,
		Issuer:         p.name,
	}, nil
}
