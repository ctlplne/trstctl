// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type certificateRevocationOrigin struct{ ExternalID, CAID string }

// A lifecycle state accepts the requested action; certificate.revoked is emitted
// only after its own authority accepts it. External serials never enter the
// platform CA's ledger or CRL. Each worker pass handles at most 100 certificates.
func (d *issuanceDispatcher) handleRevoke(ctx context.Context, m orchestrator.Message) error {
	var exact store.ExternalCertificateRevocation
	if err := json.Unmarshal(m.Payload, &exact); err != nil {
		return err
	}
	if exact.CertificateID != "" || exact.EventID != "" || exact.ExternalCAID != "" {
		return d.handleExternalCertificateRevocation(ctx, m, exact)
	}
	var trigger transitionTrigger
	if err := json.Unmarshal(m.Payload, &trigger); err != nil {
		return fmt.Errorf("server: decode revocation intent: %w", err)
	}
	if trigger.IdentityID == "" || trigger.To != string(orchestrator.StateRevoked) {
		return errors.New("server: revocation intent has no exact identity")
	}
	reason := trigger.Reason
	if reason == "" {
		reason = "unspecified"
	}
	if !crypto.IsValidRevocationReason(reason) || reason == "removeFromCRL" {
		return errors.New("server: invalid certificate revocation reason")
	}
	_, err := d.idem.Do(ctx, m.TenantID, "revoke:"+m.IdempotencyKey, func(ctx context.Context) ([]byte, error) {
		certs, err := d.store.IdentityRevocationCertificates(ctx, m.TenantID, trigger.IdentityID, 101)
		if err != nil {
			return nil, err
		}
		if len(certs) == 0 {
			found, err := d.store.IdentityHasRevocationEvidence(ctx, m.TenantID, trigger.IdentityID)
			if err != nil {
				return nil, err
			}
			if !found {
				return nil, errors.New("server: no exact certificate issuance or delivery evidence for this identity; revocation is not confirmed")
			}
		}
		more := len(certs) > 100
		if more {
			certs = certs[:100]
		}
		origins, err := d.certificateRevocationOrigins(ctx, m.TenantID, certs)
		if err != nil {
			return nil, err
		}
		var memberErrors []error
		for _, cert := range certs {
			origin := origins[cert.Fingerprint]
			if origin.ExternalID != "" {
				if err := d.revokeExternalCertificate(ctx, m.TenantID, origin.ExternalID, cert, reason); err != nil {
					// A refused predecessor must not prevent the live successor
					// from reaching its own issuer. Keep the failure retryable;
					// only confirmed members receive revocation events.
					memberErrors = append(memberErrors, err)
					continue
				}
			}
			if err := d.orch.RevokeCertificateForCA(ctx, m.TenantID, cert.Fingerprint, cert.Serial, origin.CAID, reason, crypto.CRLReasonCode(crypto.RevocationReason(reason)), time.Now().UTC()); err != nil {
				memberErrors = append(memberErrors, err)
			}
		}
		if err := errors.Join(memberErrors...); err != nil {
			return nil, err
		}
		if more {
			return nil, orchestrator.DeferDelivery(errors.New("server: confirmed one revocation page; further exact certificates remain"))
		}
		return []byte(fmt.Sprintf("revoked:%d", len(certs))), nil
	})
	// Keep publication outside the cached mutation result. If publication fails,
	// the unchanged outbox retry must retry it even after inventory is revoked.
	// Publish confirmed local members even if another member failed upstream.
	// The platform publisher reads only its own ledger; external serials are absent.
	// An external-only customer has no platform CRL surface. Consult the durable
	// issuance ledger, not the identity's mutable current CA selection: a mixed
	// customer still owes publication even when this command revoked external
	// leaves or its mutation result was already cached.
	localSurface, surfaceErr := d.store.HasIssuedCerts(ctx, m.TenantID, IssuingCAID())
	if surfaceErr != nil {
		return errors.Join(err, surfaceErr)
	}
	if !localSurface {
		return err
	}
	return errors.Join(err, d.publishTenantCRL(ctx, m.TenantID))
}

// Resolve origin from retained issuance facts, not mutable inventory source or
// the identity's current selection. Host recording overwrites source=external-ca
// with source=issued; the upstream's original event still proves who signed it.
// This single history pass resolves the entire bounded page. Missing or conflicting
// provenance refuses the page before any upstream call or revocation event.
func (d *issuanceDispatcher) certificateRevocationOrigins(ctx context.Context, tenantID string, certs []store.Certificate) (map[string]certificateRevocationOrigin, error) {
	origins := make(map[string]certificateRevocationOrigin, len(certs))
	if len(certs) == 0 {
		return origins, nil
	}
	if d.log == nil {
		return nil, errors.New("server: retained issuance evidence is unavailable for revocation")
	}
	selected := make(map[string]store.Certificate, len(certs))
	for _, cert := range certs {
		info, err := certinfo.Inspect(cert.CertificateDER)
		if err != nil || info.IsCA || info.SHA256Fingerprint != cert.Fingerprint || info.SerialNumber != cert.Serial {
			return nil, errors.New("server: revocation inventory differs from its public certificate")
		}
		selected[cert.Fingerprint] = cert
	}
	err := d.log.Replay(ctx, 0, func(event events.Event) error {
		if event.TenantID != tenantID || event.Type != projections.EventCertificateRecorded {
			return nil
		}
		var fact projections.CertificateRecorded
		if err := json.Unmarshal(event.Data, &fact); err != nil {
			return err
		}
		cert, ok := selected[fact.Fingerprint]
		if !ok {
			return nil
		}
		if err := projections.ValidateSchemaVersion(event); err != nil {
			return err
		}
		var origin certificateRevocationOrigin
		if strings.HasPrefix(fact.Source, "external-ca:") {
			origin.ExternalID = strings.TrimPrefix(fact.Source, "external-ca:")
			// Only the upstream worker produces this event identity and authenticated
			// request binding. A tenant-authored inventory source is not issuer proof.
			expected := uuid.NewSHA1(uuid.NameSpaceOID, []byte(tenantID+"\x00certificate.recorded\x00"+fact.IssuanceIdempotencyKey)).String()
			if origin.ExternalID == "" || fact.IssuanceIdempotencyKey == "" || len(fact.IssuanceRequestBinding) != 64 || event.ID != expected {
				return nil
			}
		} else if fact.Source == "issued" && fact.CAID == IssuingCAID() {
			issuer, err := certinfo.LeafDER(d.chainPEM)
			if err != nil || crypto.VerifyLeafSignedByCA(cert.CertificateDER, issuer) != nil {
				return errors.New("server: certificate was not signed by the served revocation authority")
			}
			origin.CAID = fact.CAID
		} else {
			return nil
		}
		if !bytes.Equal(fact.CertificateDER, cert.CertificateDER) || fact.Serial != cert.Serial {
			return errors.New("server: retained issuance certificate differs from revocation selection")
		}
		if prior, ok := origins[cert.Fingerprint]; ok && prior != origin {
			return errors.New("server: certificate has conflicting retained issuing authorities")
		}
		origins[cert.Fingerprint] = origin
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, cert := range certs {
		if _, ok := origins[cert.Fingerprint]; !ok {
			return nil, fmt.Errorf("server: certificate %s has no verified supported issuing authority; no CA was substituted", cert.ID)
		}
	}
	return origins, nil
}

func (d *issuanceDispatcher) revokeExternalCertificate(ctx context.Context, tenantID, authorityID string, cert store.Certificate, reason string) error {
	if d.externalCAs == nil {
		return errors.New("server: recorded external revocation authority is unavailable; no CA was substituted")
	}
	entry, ok := d.externalCAs.byID[authorityID]
	if !ok || entry.tenantID != "" && entry.tenantID != tenantID || entry.revocationCA == nil {
		return errors.New("server: recorded external revocation authority is unavailable for this tenant; no CA was substituted")
	}
	err := ca.RevokeThrough(ctx, entry.revocationCA, ca.RevokeRequest{TenantID: tenantID, Serial: cert.Serial, CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.CertificateDER}), ReasonCode: crypto.CRLReasonCode(crypto.RevocationReason(reason))})
	if errors.Is(err, ca.ErrRevocationUnsupported) {
		return errors.New("server: recorded external authority does not support revocation through this integration; use its issuing CA")
	}
	if err != nil {
		return fmt.Errorf("server: external certificate revocation not confirmed: %s", externalCAUpstreamDetail(err))
	}
	return nil
}
