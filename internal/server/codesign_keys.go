// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Code-signing key certificates (P9). A managed code-signing key signs only
// inside the isolated signer, but stock signing tools — jarsigner,
// osslsigncode, Notation — also need the certificate that names the key. The
// chain is attached through the API (P9-L1: checked against the key's public
// key and the codeSigning usage, recorded as codesign.certificate_attached,
// served on every replica from the next request on), or configured beside the
// key (code_signing.keys[].certificate_chain_file, checked at startup); an
// attached chain wins. A certificate request for the key is signed inside the
// signer, so any CA — trstctl's or a vendor's — can issue that certificate.

// KeyCertificate returns the key's chain and public key: the chain attached
// through the API, or else the configured one.
func (s *servedCodeSigningService) KeyCertificate(ctx context.Context, tenantID, keyID string) (api.CodeSigningKeyCertificate, error) {
	signer, err := s.codeSigningKey(tenantID, keyID)
	if err != nil {
		return api.CodeSigningKeyCertificate{}, err
	}
	if s.store != nil {
		attached, err := s.store.GetCodeSigningKeyCertificate(ctx, tenantID, keyID)
		switch {
		case err == nil:
			at := attached.AttachedAt
			return describeCodeSigningChain(keyID, signer, attached.ChainDER, "attached", attached.AttachedBy, &at)
		case !store.IsNotFound(err):
			return api.CodeSigningKeyCertificate{}, err
		}
	}
	chain := s.cfg.KeyCertificates[codeSigningKeyIdentity(tenantID, keyID)]
	if len(chain) == 0 {
		return api.CodeSigningKeyCertificate{}, api.ErrNoCodeSigningKeyCertificate
	}
	return describeCodeSigningChain(keyID, signer, chain, "configured", "", nil)
}

func describeCodeSigningChain(keyID string, signer crypto.DigestSigner, chain [][]byte, source, attachedBy string, attachedAt *time.Time) (api.CodeSigningKeyCertificate, error) {
	leaf, err := certinfo.Inspect(chain[0])
	if err != nil {
		return api.CodeSigningKeyCertificate{}, fmt.Errorf("codesign: %s leaf: %w", source, err)
	}
	var out strings.Builder
	for _, der := range chain {
		out.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	return api.CodeSigningKeyCertificate{
		KeyID: keyID, Algorithm: string(signer.Algorithm()), PublicKeyDER: append([]byte(nil), signer.Public().DER...),
		ChainPEM: out.String(), LeafFingerprint: leaf.SHA256Fingerprint, NotAfter: leaf.NotAfter,
		CodeSigningEKU: hasExtKeyUsage(leaf.ExtKeyUsages, "codeSigning"),
		Source:         source, AttachedBy: attachedBy, AttachedAt: attachedAt,
	}, nil
}

// maxCodeSigningChainCertificates bounds an attached chain.
const maxCodeSigningChainCertificates = 10

// AttachKeyCertificate attaches or rotates the key's chain (P9-L1). The chain
// is checked exactly as a configured one is at startup — its leaf names the
// key and may sign code — and also must not have expired; then it is recorded
// as codesign.certificate_attached and read from the next request on. The
// idempotency key names the attachment, so a retried request records it once.
func (s *servedCodeSigningService) AttachKeyCertificate(ctx context.Context, tenantID, principal, keyID, chainPEM, idempotencyKey string) (api.CodeSigningKeyCertificate, error) {
	signer, err := s.codeSigningKey(tenantID, keyID)
	if err != nil {
		return api.CodeSigningKeyCertificate{}, err
	}
	if s.store == nil || s.log == nil {
		return api.CodeSigningKeyCertificate{}, errors.New("codesign: attaching a chain needs the store and the event log")
	}
	chain, err := loadCodeSigningKeyChain([]byte(chainPEM), signer)
	if err != nil {
		return api.CodeSigningKeyCertificate{}, fmt.Errorf("%w: %v", api.ErrCodeSigningChainInvalid, err)
	}
	if len(chain) > maxCodeSigningChainCertificates {
		return api.CodeSigningKeyCertificate{}, fmt.Errorf("%w: a chain holds at most %d certificates", api.ErrCodeSigningChainInvalid, maxCodeSigningChainCertificates)
	}
	leaf, err := certinfo.Inspect(chain[0])
	if err != nil {
		return api.CodeSigningKeyCertificate{}, fmt.Errorf("%w: leaf: %v", api.ErrCodeSigningChainInvalid, err)
	}
	if !time.Now().Before(leaf.NotAfter) {
		return api.CodeSigningKeyCertificate{}, fmt.Errorf("%w: the leaf certificate expired at %s", api.ErrCodeSigningChainInvalid, leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	attachment := codeSigningOperationID(tenantID, "certificate:"+keyID+":"+idempotencyKey)
	if err := s.appendAndProject(ctx, tenantID, projections.EventCodeSigningCertificateAttached, attachment,
		projections.CodeSigningCertificateAttached{
			KeyID: keyID, ChainDER: chain, LeafFingerprint: strings.ToLower(leaf.SHA256Fingerprint),
			NotAfter: leaf.NotAfter.UTC(), AttachedBy: principal,
		}); err != nil {
		return api.CodeSigningKeyCertificate{}, fmt.Errorf("codesign: record the attached chain: %w", err)
	}
	return s.KeyCertificate(ctx, tenantID, keyID)
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
