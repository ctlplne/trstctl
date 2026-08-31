// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// certificateRevocationAuthority accepts only a leaf actually signed by this
// served authority. Imported certificates remain inventory, not an invitation
// to revoke an unrelated local leaf with the same serial. Other authority paths
// must supply their own verified adapter; there is no internal-CA fallback.
func (s *Server) certificateRevocationAuthority(ctx context.Context, certificate store.Certificate) (string, error) {
	if s.revoc == nil {
		return "", errors.New("server: certificate revocation publication is unavailable")
	}
	leafDER, err := certinfo.LeafDER(certificate.CertificateDER)
	if err != nil {
		return "", orchestrator.ErrCertificateRevocationUnsupported
	}
	info, err := certinfo.Inspect(leafDER)
	if err != nil || info.IsCA || info.SHA256Fingerprint != certificate.Fingerprint || info.SerialNumber != certificate.Serial {
		return "", orchestrator.ErrCertificateRevocationUnsupported
	}
	if err := crypto.VerifyLeafSignedByCA(leafDER, s.revoc.caCertDER); err != nil {
		return "", orchestrator.ErrCertificateRevocationUnsupported
	}
	_, found, err := s.store.LookupIssuedCert(ctx, certificate.TenantID, s.revoc.caID, certificate.Serial)
	if err != nil {
		return "", err
	}
	if !found {
		return "", orchestrator.ErrCertificateRevocationUnsupported
	}
	return s.revoc.caID, nil
}

// handleCertificateCRLPublication has no issuance or identity fan-out. The
// certificate and CA ledger already committed with this intent; the worker
// publishes that authority's signed view and retains failures for retry.
func (d *issuanceDispatcher) handleCertificateCRLPublication(ctx context.Context, message orchestrator.Message) error {
	var command store.CertificateCRLPublication
	if err := json.Unmarshal(message.Payload, &command); err != nil {
		return fmt.Errorf("server: decode certificate CRL publication: %w", err)
	}
	if command.EventID == "" || command.CAID != IssuingCAID() || d.publishCRL == nil {
		return errors.New("server: requested certificate CRL authority is not served")
	}
	return d.publishCRL(ctx, message.TenantID)
}
