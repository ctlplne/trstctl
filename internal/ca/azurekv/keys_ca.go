// SPDX-License-Identifier: BUSL-1.1

package azurekv

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/catemplate"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

const defaultKeysCAValidity = 90 * 24 * time.Hour

// KeysCAConfig binds an operator-provisioned CA certificate chain to the matching
// Key Vault/Managed-HSM signing key. CACertificatePEM is public material ordered
// issuer first, then parents. The private key remains in Azure.
type KeysCAConfig struct {
	Name             string
	CACertificatePEM []byte
	DefaultTTL       time.Duration
}

type keysBackend struct {
	cfg       KeysCAConfig
	caDER     []byte
	signer    crypto.DigestSigner
	destroy   func()
	destroyed bool
}

// NewKeysCA constructs the native Azure Keys/Managed-HSM CA. It rejects a chain
// whose first CA certificate does not match the remote key's real JWK public key,
// so a typo cannot create certificates that fail verification after signing.
func NewKeysCA(cfg KeysCAConfig, signer crypto.DigestSigner, destroy func()) (*catemplate.Plugin, error) {
	if signer == nil {
		return nil, errors.New("azurekv: native keys CA requires a remote signer")
	}
	block, _ := pem.Decode(cfg.CACertificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("azurekv: native keys CA chain must start with a CERTIFICATE PEM block")
	}
	info, err := certinfo.Inspect(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("azurekv: inspect native CA certificate: %w", err)
	}
	if !info.IsCA || !info.KeyUsageCertSign {
		return nil, errors.New("azurekv: native keys certificate is not a certificate-signing CA")
	}
	certPublic, err := crypto.PublicKeyDERFromCert(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("azurekv: native CA public key: %w", err)
	}
	if !bytes.Equal(certPublic, signer.Public().DER) {
		return nil, errors.New("azurekv: native CA certificate public key does not match the configured Azure key")
	}
	if cfg.Name == "" {
		cfg.Name = "azure-key-vault"
	}
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = defaultKeysCAValidity
	}
	cfg.CACertificatePEM = append([]byte(nil), cfg.CACertificatePEM...)
	return catemplate.New(&keysBackend{
		cfg: cfg, caDER: append([]byte(nil), block.Bytes...), signer: signer, destroy: destroy,
	}), nil
}

func (b *keysBackend) CAName() string { return b.cfg.Name }

func (b *keysBackend) Issue(_ context.Context, req ca.IssueRequest) ([]byte, error) {
	if b.destroyed {
		return nil, errors.New("azurekv: native keys CA was destroyed")
	}
	if len(req.DNSNames) == 0 {
		return nil, errors.New("azurekv: at least one DNS name is required")
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = b.cfg.DefaultTTL
	}
	leafDER, err := crypto.SignLeafFromCSR(b.caDER, b.signer, req.CSR, ttl)
	if err != nil {
		return nil, fmt.Errorf("azurekv: sign leaf through Azure key: %w", err)
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	chain = append(chain, b.cfg.CACertificatePEM...)
	return chain, nil
}

func (b *keysBackend) Destroy() {
	if b.destroyed {
		return
	}
	b.destroyed = true
	if b.destroy != nil {
		b.destroy()
	}
	b.signer = nil
}
