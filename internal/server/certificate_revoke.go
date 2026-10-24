// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// ensureIssuedCredentialCRL completes the same trusted initial-publication step
// used by ordinary and protocol issuance. The certificate event and CA ledger
// are already durable. If local signed-public-material publication fails, the
// caller receives a failure; its unchanged authorized retry recovers that same
// recorded leaf and retries publication, never another leaf signature.
//
// This uses the existing isolated signer and ca.crl.published event path. It does
// not make an upstream CA/connector call, write projections directly, or turn an
// anonymous GET into a signing command. The retained issuance event also makes
// the missing CRL discoverable by startup/freshness reconciliation after a crash.
func (s *Server) ensureIssuedCredentialCRL(ctx context.Context, tenantID string) error {
	if s.revoc == nil {
		return errors.New("server: initial credential CRL publication is unavailable")
	}
	if err := s.revoc.ensureCRL(ctx, tenantID); err != nil {
		return fmt.Errorf("server: initial credential CRL publication failed; retry the unchanged issuance command: %w", err)
	}
	return nil
}

// certificateRevocationAuthority accepts only a leaf actually signed by this
// served authority. Imported certificates remain inventory, not an invitation
// to revoke an unrelated local leaf with the same serial. Other authority paths
// must supply their own verified adapter; there is no internal-CA fallback.
func (s *Server) certificateRevocationAuthority(ctx context.Context, certificate store.Certificate) (string, error) {
	// Host recording can change source to "issued". The original immutable
	// upstream certificate event, never a mutable name or current identity CA,
	// binds this exact public leaf to its external revocation authority.
	if dispatcher, ok := s.obHandler.(*issuanceDispatcher); ok && dispatcher.externalCAs != nil {
		origins, err := dispatcher.certificateRevocationOrigins(ctx, certificate.TenantID, []store.Certificate{certificate})
		if err == nil {
			origin := origins[certificate.Fingerprint]
			if origin.ExternalID != "" {
				entry, found := dispatcher.externalCAs.byID[origin.ExternalID]
				if !found || !entry.canRevoke() || (entry.tenantID != "" && entry.tenantID != certificate.TenantID) {
					return "", orchestrator.ErrCertificateRevocationUnsupported
				}
				return orchestrator.ExternalCertificateAuthorityPrefix + origin.ExternalID, nil
			}
		}
	}
	if s.caHierarchy != nil && certificate.IssuanceEventID != "" {
		event, found, err := s.log.EventByID(ctx, certificate.IssuanceEventID)
		if err != nil {
			return "", err
		}
		if found && event.Type == projections.EventCACertificateInventoryRecovered {
			if authority, resolved, err := s.recoveredLeafRevocationAuthority(ctx, certificate, event); resolved || err != nil {
				return authority, err
			}
		}
		managed, err := projections.LegacyManagedCALeafEvidence(event)
		if err != nil {
			return "", orchestrator.ErrCertificateRevocationUnsupported
		}
		if found && managed {
			if event.TenantID != certificate.TenantID ||
				projections.LegacyManagedCAInventoryID(event) != certificate.ID {
				return "", orchestrator.ErrCertificateRevocationUnsupported
			}
			var origin projections.CAIssuedCertificate
			if json.Unmarshal(event.Data, &origin) != nil || origin.CAID == "" ||
				origin.Fingerprint != certificate.Fingerprint || origin.Serial != certificate.Serial ||
				!bytes.Equal(origin.CertificateDER, certificate.CertificateDER) {
				return "", orchestrator.ErrCertificateRevocationUnsupported
			}
			info, err := certinfo.Inspect(origin.CertificateDER)
			if err != nil || info.IsCA || info.SHA256Fingerprint != origin.Fingerprint ||
				info.SerialNumber != origin.Serial {
				return "", orchestrator.ErrCertificateRevocationUnsupported
			}
			authority, err := s.store.GetCAAuthority(ctx, certificate.TenantID, origin.CAID)
			if store.IsNotFound(err) || authority.SignerHandle == "" {
				return "", orchestrator.ErrCertificateRevocationUnsupported
			}
			if err != nil {
				return "", err
			}
			issuerDER, err := firstCertDER(authority.CertificatePEM)
			if err != nil || crypto.VerifyLeafSignedByCA(origin.CertificateDER, issuerDER) != nil {
				return "", orchestrator.ErrCertificateRevocationUnsupported
			}
			_, found, err := s.store.LookupIssuedCert(ctx, certificate.TenantID, origin.CAID, origin.Serial)
			if err != nil {
				return "", err
			}
			if !found {
				return "", orchestrator.ErrCertificateRevocationUnsupported
			}
			if destroyed, err := caKeyDestroyed(ctx, s.caKeyRetirementState, certificate.TenantID, origin.CAID); err != nil {
				return "", err
			} else if destroyed {
				return "", orchestrator.ErrCertificateAuthorityKeyDestroyed
			}
			return origin.CAID, nil
		}
		if found && event.Type == projections.EventCAEndEntityIssued && event.SchemaVersion == projections.CAEndEntityInventorySchemaVersion {
			if event.TenantID != certificate.TenantID {
				return "", orchestrator.ErrCertificateRevocationUnsupported
			}
			var origin projections.CAEndEntityInventoried
			if json.Unmarshal(event.Data, &origin) != nil || origin.ID != certificate.ID ||
				origin.Fingerprint != certificate.Fingerprint || origin.Serial != certificate.Serial ||
				!bytes.Equal(origin.CertificateDER, certificate.CertificateDER) {
				return "", orchestrator.ErrCertificateRevocationUnsupported
			}
			authority, err := s.store.GetCAAuthority(ctx, certificate.TenantID, origin.CAID)
			if store.IsNotFound(err) || authority.SignerHandle == "" {
				return "", orchestrator.ErrCertificateRevocationUnsupported
			}
			if err != nil {
				return "", err
			}
			issuerDER, err := firstCertDER(authority.CertificatePEM)
			if err != nil || crypto.VerifyLeafSignedByCA(origin.CertificateDER, issuerDER) != nil {
				return "", orchestrator.ErrCertificateRevocationUnsupported
			}
			_, found, err := s.store.LookupIssuedCert(ctx, certificate.TenantID, origin.CAID, certificate.Serial)
			if err != nil {
				return "", err
			}
			if !found {
				return "", orchestrator.ErrCertificateRevocationUnsupported
			}
			if destroyed, err := caKeyDestroyed(ctx, s.caKeyRetirementState, certificate.TenantID, origin.CAID); err != nil {
				return "", err
			} else if destroyed {
				return "", orchestrator.ErrCertificateAuthorityKeyDestroyed
			}
			return origin.CAID, nil
		}
	}
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

// recoveredLeafRevocationAuthority resolves a recovered historical leaf
// (A111, A113) by its recovery event, which names the CA its original mint
// did. resolved is false for a leaf of the issuing CA: it continues to the
// served revocation authority. A managed CA's leaf is checked against that CA.
func (s *Server) recoveredLeafRevocationAuthority(ctx context.Context, certificate store.Certificate, event events.Event) (string, bool, error) {
	var recovered projections.CACertificateInventoryRecovered
	if json.Unmarshal(event.Data, &recovered) != nil || event.TenantID != certificate.TenantID ||
		projections.RecoveredInventoryID(event.TenantID, recovered) != certificate.ID ||
		recovered.Fingerprint != certificate.Fingerprint || recovered.Serial != certificate.Serial ||
		!bytes.Equal(recovered.CertificateDER, certificate.CertificateDER) {
		return "", true, orchestrator.ErrCertificateRevocationUnsupported
	}
	if recovered.CAID == IssuingCAID() {
		return "", false, nil
	}
	authority, err := s.managedLeafRevocationAuthority(ctx, certificate.TenantID, recovered.CAID, recovered.CertificateDER, recovered.Serial)
	return authority, true, err
}

// managedLeafRevocationAuthority returns the managed CA that signed der and
// whose ledger holds serial, refusing a CA without a signer, a leaf it did not
// sign, a serial it never minted, and a CA whose key was destroyed.
func (s *Server) managedLeafRevocationAuthority(ctx context.Context, tenantID, caID string, der []byte, serial string) (string, error) {
	authority, err := s.store.GetCAAuthority(ctx, tenantID, caID)
	if store.IsNotFound(err) || (err == nil && authority.SignerHandle == "") {
		return "", orchestrator.ErrCertificateRevocationUnsupported
	}
	if err != nil {
		return "", err
	}
	issuerDER, err := firstCertDER(authority.CertificatePEM)
	if err != nil || crypto.VerifyLeafSignedByCA(der, issuerDER) != nil {
		return "", orchestrator.ErrCertificateRevocationUnsupported
	}
	if _, found, err := s.store.LookupIssuedCert(ctx, tenantID, caID, serial); err != nil {
		return "", err
	} else if !found {
		return "", orchestrator.ErrCertificateRevocationUnsupported
	}
	if destroyed, err := caKeyDestroyed(ctx, s.caKeyRetirementState, tenantID, caID); err != nil {
		return "", err
	} else if destroyed {
		return "", orchestrator.ErrCertificateAuthorityKeyDestroyed
	}
	return caID, nil
}

// handleCertificateCRLPublication has no issuance or identity fan-out. The
// certificate and CA ledger already committed with this intent; the worker
// publishes that authority's signed view and retains failures for retry.
func (d *issuanceDispatcher) handleCertificateCRLPublication(ctx context.Context, message orchestrator.Message) error {
	var command store.CertificateCRLPublication
	if err := json.Unmarshal(message.Payload, &command); err != nil {
		return fmt.Errorf("server: decode certificate CRL publication: %w", err)
	}
	if command.EventID == "" || command.CAID == "" {
		return errors.New("server: requested certificate CRL authority is not served")
	}
	if command.CAID == IssuingCAID() {
		if d.publishCRL == nil {
			return errors.New("server: requested certificate CRL authority is not served")
		}
		return d.publishCRL(ctx, message.TenantID)
	}
	if d.publishAuthorityCRL == nil {
		return errors.New("server: requested managed CA CRL authority is not served")
	}
	return d.publishAuthorityCRL(ctx, message.TenantID, command.CAID)
}

// caKeyDestroyed reports whether a managed CA authority's signing key has a
// signed destruction record. Without an attached retirement state source no
// key is treated as destroyed; the resolver then relies on its signer checks.
func caKeyDestroyed(ctx context.Context, state func(context.Context, string, string) (string, bool, error), tenantID, keyID string) (bool, error) {
	if state == nil || keyID == "" {
		return false, nil
	}
	status, found, err := state(ctx, tenantID, keyID)
	if err != nil {
		return false, err
	}
	return found && status == "destroyed", nil
}
