// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// Code-signing key certificates (P9). A managed code-signing key signs only
// inside the isolated signer, but stock signing tools — jarsigner,
// osslsigncode, Notation — also need the certificate that names the key. The
// chain is configured beside the key (code_signing.keys[].certificate_chain_file),
// checked at startup against the key's public key, and served read-only. A
// certificate request for the key is signed inside the signer, so any CA —
// trstctl's or a vendor's — can issue that certificate.

// KeyCertificate returns the key's configured chain and public key.
func (s *servedCodeSigningService) KeyCertificate(_ context.Context, tenantID, keyID string) (api.CodeSigningKeyCertificate, error) {
	signer, err := s.codeSigningKey(tenantID, keyID)
	if err != nil {
		return api.CodeSigningKeyCertificate{}, err
	}
	chain := s.cfg.KeyCertificates[codeSigningKeyIdentity(tenantID, keyID)]
	if len(chain) == 0 {
		return api.CodeSigningKeyCertificate{}, api.ErrNoCodeSigningKeyCertificate
	}
	leaf, err := certinfo.Inspect(chain[0])
	if err != nil {
		return api.CodeSigningKeyCertificate{}, fmt.Errorf("codesign: configured leaf: %w", err)
	}
	var out strings.Builder
	for _, der := range chain {
		out.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	return api.CodeSigningKeyCertificate{
		KeyID: keyID, Algorithm: string(signer.Algorithm()), PublicKeyDER: append([]byte(nil), signer.Public().DER...),
		ChainPEM: out.String(), LeafFingerprint: leaf.SHA256Fingerprint, NotAfter: leaf.NotAfter,
		CodeSigningEKU: hasExtKeyUsage(leaf.ExtKeyUsages, "codeSigning"),
	}, nil
}

// KeyCSR returns a PKCS #10 request for the key, signed inside the signer,
// asking for the codeSigning extended key usage. The use of the key is recorded
// (codesign.csr_signed) before the request is returned.
func (s *servedCodeSigningService) KeyCSR(ctx context.Context, tenantID, principal, keyID string, req api.CodeSigningKeyCSRRequest) ([]byte, error) {
	signer, err := s.codeSigningKey(tenantID, keyID)
	if err != nil {
		return nil, err
	}
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: strings.TrimSpace(req.CommonName), RequestedEKUs: []string{"codeSigning"},
	}, signer)
	if err != nil {
		return nil, fmt.Errorf("codesign: sign the certificate request: %w", err)
	}
	record, err := json.Marshal(map[string]string{"principal": principal, "key": keyID, "csr_sha256": crypto.SHA256Hex(csrDER)})
	if err != nil {
		return nil, err
	}
	if err := (codeSigningEventAuditor{log: s.log}).Audit(ctx, eventCodeSigningCSRSigned, tenantID, record); err != nil {
		return nil, fmt.Errorf("codesign: record the certificate request: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

const eventCodeSigningCSRSigned = "codesign.csr_signed"

func (s *servedCodeSigningService) codeSigningKey(tenantID, keyID string) (crypto.DigestSigner, error) {
	if s.cfg.Keys == nil || strings.TrimSpace(keyID) == "" {
		return nil, api.ErrCodeSigningKeyNotFound
	}
	signer, err := s.cfg.Keys.Signer(tenantID, keyID)
	if err != nil || signer == nil {
		return nil, api.ErrCodeSigningKeyNotFound
	}
	return signer, nil
}

func hasExtKeyUsage(usages []string, want string) bool {
	for _, usage := range usages {
		if usage == want {
			return true
		}
	}
	return false
}

// loadCodeSigningKeyChain reads a configured chain (leaf first) and checks it
// names the key: the leaf's public key must be the signer's.
func loadCodeSigningKeyChain(raw []byte, signer crypto.DigestSigner) ([][]byte, error) {
	var chain [][]byte
	for rest := raw; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			chain = append(chain, block.Bytes)
		}
	}
	if len(chain) == 0 {
		return nil, errors.New("the file holds no PEM certificate")
	}
	leaf, err := certinfo.Inspect(chain[0])
	if err != nil {
		return nil, fmt.Errorf("leaf: %w", err)
	}
	if !strings.EqualFold(leaf.SPKISHA256, crypto.SHA256Hex(signer.Public().DER)) {
		return nil, errors.New("the leaf certificate does not name this key")
	}
	if !hasExtKeyUsage(leaf.ExtKeyUsages, "codeSigning") {
		return nil, errors.New("the leaf certificate lacks the codeSigning extended key usage")
	}
	return chain, nil
}
