// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Historical leaves (A111, A113). Before ca.certificate.issued v3, a
// PKI-secret mint projected only its responder serial: v2 retained the public
// leaf, v1 only the serial. Neither had an inventory row, so the inventory
// revocation workflow could not reach the leaf. The control plane recovers a
// v2 leaf from its own retained evidence, after checking it against the
// issuing CA's certificate this process holds; the projector checks the same
// facts again. Custody stays unknown, and a leaf this CA did not sign is left
// as serial evidence. The same recovery gives a managed CA leaf recorded only
// in the v2 responder form of ca.endentity.issued its inventory row, checked
// against that managed CA's stored certificate, when no other event already
// inventoried the leaf.

var pkiSecretRecoveryNamespace = uuid.MustParse("7d3f0a52-1c7b-4b9e-a2a1-5f0e6c1d2b84")

// pkiSecretRecoveryEventID is the one recovery event an original mint gets.
func pkiSecretRecoveryEventID(tenantID, originalEventID string) string {
	return uuid.NewSHA1(pkiSecretRecoveryNamespace, []byte(tenantID+"\x00"+originalEventID)).String()
}

// pkiSecretRecovery counts one recovery pass.
type pkiSecretRecovery struct {
	Recovered        int
	AlreadyRecovered int
	InInventory      int
	Unverifiable     int
}

type pkiSecretRecoveryCandidate struct {
	event    events.Event
	issued   projections.CAIssuedCertificate
	evidence string
}

// recoverLegacyPKISecretInventory recovers every retained v2 leaf that has no
// inventory row yet and that its CA signed: PKI-secret leaves of the issuing
// CA this process holds (A111), and managed CA leaves an issuance surface
// recorded in the v2 responder form, checked against that CA's stored
// certificate (A113). A retry converges: each original mint has one
// deterministic recovery event.
func (s *Server) recoverLegacyPKISecretInventory(ctx context.Context) (pkiSecretRecovery, error) {
	var out pkiSecretRecovery
	if s.log == nil || s.store == nil {
		return out, nil
	}
	issuingCAID := IssuingCAID()
	var candidates []pkiSecretRecoveryCandidate
	err := s.log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		head, err := s.log.LastSequence(readCtx)
		if err != nil || head == 0 {
			return err
		}
		return s.log.ReplayTypesThrough(readCtx, 1, head,
			[]string{projections.EventCAIssuedCertificate, projections.EventCAEndEntityIssued}, func(e events.Event) error {
				if e.SchemaVersion != projections.CAIssuedCertificateEvidenceSchemaVersion {
					return nil
				}
				var issued projections.CAIssuedCertificate
				if err := json.Unmarshal(e.Data, &issued); err != nil {
					return fmt.Errorf("server: decode historical mint %s: %w", e.ID, err)
				}
				if len(issued.CertificateDER) == 0 {
					return nil
				}
				switch e.Type {
				case projections.EventCAIssuedCertificate:
					if issued.Source == "pkisecret" {
						candidates = append(candidates, pkiSecretRecoveryCandidate{event: e, issued: issued, evidence: projections.RecoveredFromRetainedLeaf})
					}
				case projections.EventCAEndEntityIssued:
					// A v2 hierarchy mint with a subject is projected into inventory
					// by the projector itself; only the responder form needs this.
					managed, err := projections.LegacyManagedCALeafEvidence(e)
					if err != nil {
						return err
					}
					if !managed {
						candidates = append(candidates, pkiSecretRecoveryCandidate{event: e, issued: issued, evidence: projections.RecoveredFromRetainedResponderLeaf})
					}
				}
				return nil
			})
	})
	if err != nil {
		return out, err
	}
	for _, c := range candidates {
		issuerDER, err := s.historicalLeafIssuer(ctx, c, issuingCAID)
		if err != nil {
			return out, err
		}
		info, err := certinfo.Inspect(c.issued.CertificateDER)
		if err != nil || issuerDER == nil || info.IsCA || info.SerialNumber != c.issued.Serial ||
			info.SHA256Fingerprint != c.issued.Fingerprint || crypto.VerifyLeafSignedByCA(c.issued.CertificateDER, issuerDER) != nil {
			out.Unverifiable++
			continue
		}
		recoveryID := pkiSecretRecoveryEventID(c.event.TenantID, c.event.ID)
		if _, found, err := s.log.EventByID(ctx, recoveryID); err != nil {
			return out, err
		} else if found {
			out.AlreadyRecovered++
			continue
		}
		if _, err := s.store.GetCertificateByFingerprint(ctx, c.event.TenantID, c.issued.Fingerprint); err == nil {
			// Another event already inventoried this leaf (a protocol issuance
			// or an import, say); recovery adds no second row and changes none.
			out.InInventory++
			continue
		} else if !store.IsNotFound(err) {
			return out, err
		}
		if err := s.appendPKISecretRecovery(ctx, c.event.TenantID, c.event.ID, recoveryID, c.issued.CAID, c.issued.Serial,
			c.issued.Fingerprint, c.issued.CertificateDER, issuerDER, c.evidence); err != nil {
			return out, err
		}
		out.Recovered++
	}
	return out, nil
}

// historicalLeafIssuer is the CA certificate a historical leaf must verify
// against, or nil when this control plane cannot name it: the issuing CA it
// holds for PKI secrets, or the managed CA's stored certificate.
func (s *Server) historicalLeafIssuer(ctx context.Context, c pkiSecretRecoveryCandidate, issuingCAID string) ([]byte, error) {
	if c.evidence == projections.RecoveredFromRetainedLeaf {
		if c.issued.CAID != issuingCAID || len(s.caCertDER) == 0 {
			return nil, nil
		}
		return s.caCertDER, nil
	}
	authority, err := s.store.GetCAAuthority(ctx, c.event.TenantID, c.issued.CAID)
	if store.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	der, err := firstCertDER(authority.CertificatePEM)
	if err != nil {
		return nil, nil
	}
	return der, nil
}

func (s *Server) appendPKISecretRecovery(ctx context.Context, tenantID, originalEventID, recoveryID, caID, serial, fingerprint string, der, issuerDER []byte, evidence string) error {
	payload, err := json.Marshal(projections.CACertificateInventoryRecovered{
		OriginalEventID: originalEventID, CAID: caID, Serial: serial, Fingerprint: fingerprint,
		CertificateDER: der, IssuerCertificateDER: issuerDER, Evidence: evidence, RecoveredAt: time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	stored, err := s.log.Append(ctx, events.Event{ID: recoveryID, Type: projections.EventCACertificateInventoryRecovered,
		TenantID: tenantID, Data: payload})
	if err != nil {
		return err
	}
	if stored.Type != projections.EventCACertificateInventoryRecovered || stored.TenantID != tenantID {
		return errors.New("server: PKI secret recovery event identity differs")
	}
	return projections.New(s.store).Apply(ctx, stored)
}

// runPKISecretInventoryRecoveryOnce runs recovery until one pass completes;
// later sweeps skip it. A pass that fails is retried on the next sweep.
func (s *Server) runPKISecretInventoryRecoveryOnce(ctx context.Context) {
	if s.pkiSecretRecoveryDone.Load() {
		return
	}
	result, err := s.recoverLegacyPKISecretInventory(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("PKI secret inventory recovery incomplete; retrying on the next sweep", slog.String("error", err.Error()))
		}
		return
	}
	s.pkiSecretRecoveryDone.Store(true)
	if s.logger != nil && (result.Recovered > 0 || result.Unverifiable > 0) {
		s.logger.Info("PKI secret inventory recovery",
			slog.Int("recovered", result.Recovered), slog.Int("already_recovered", result.AlreadyRecovered),
			slog.Int("in_inventory", result.InInventory), slog.Int("unverifiable", result.Unverifiable))
	}
}

// RecoverPKISecretLeaf gives a historical PKI-secret leaf its inventory row
// from the public certificate an operator supplies (A111). A v1 mint kept
// only the serial, so the certificate is accepted only when this control
// plane's issuing CA signed it and a PKI-secret mint recorded its serial; a
// v2 mint must have retained exactly these bytes. Retrying returns the same
// row.
func (s *Server) RecoverPKISecretLeaf(ctx context.Context, tenantID string, certificatePEM []byte) (api.PKISecretLeafRecovery, error) {
	if s.log == nil || s.store == nil || len(s.caCertDER) == 0 {
		return api.PKISecretLeafRecovery{}, errors.New("server: PKI secret leaf recovery requires the issuing CA and event log")
	}
	der, err := certinfo.LeafDER(certificatePEM)
	if err != nil {
		return api.PKISecretLeafRecovery{}, fmt.Errorf("%w: the body is not one PEM certificate: %v", api.ErrPKISecretLeafNotRecoverable, err)
	}
	info, err := certinfo.Inspect(der)
	if err != nil || info.IsCA {
		return api.PKISecretLeafRecovery{}, fmt.Errorf("%w: the certificate is not an end-entity leaf", api.ErrPKISecretLeafNotRecoverable)
	}
	if crypto.VerifyLeafSignedByCA(der, s.caCertDER) != nil {
		return api.PKISecretLeafRecovery{}, fmt.Errorf("%w: this control plane's issuing CA did not sign the certificate", api.ErrPKISecretLeafNotRecoverable)
	}
	mint, issued, found, err := s.pkiSecretMintForSerial(ctx, tenantID, info.SerialNumber)
	if err != nil {
		return api.PKISecretLeafRecovery{}, err
	}
	if !found {
		return api.PKISecretLeafRecovery{}, fmt.Errorf("%w: no PKI secret mint recorded serial %s", api.ErrPKISecretLeafNotRecoverable, info.SerialNumber)
	}
	evidence := projections.RecoveredFromOperatorLeaf
	switch mint.SchemaVersion {
	case projections.CASecretInventorySchemaVersion:
		return api.PKISecretLeafRecovery{}, fmt.Errorf("%w: its mint already inventoried it as %s", api.ErrPKISecretLeafInInventory,
			projections.SecretPKIInventoryID(mint))
	case projections.CAIssuedCertificateEvidenceSchemaVersion:
		if !bytes.Equal(issued.CertificateDER, der) {
			return api.PKISecretLeafRecovery{}, fmt.Errorf("%w: its mint retained a different certificate for serial %s", api.ErrPKISecretLeafNotRecoverable, info.SerialNumber)
		}
		evidence = projections.RecoveredFromRetainedLeaf
	}
	out := api.PKISecretLeafRecovery{
		CertificateID: projections.RecoveredSecretPKIInventoryID(tenantID, mint.ID), Serial: info.SerialNumber,
		Fingerprint: info.SHA256Fingerprint, OriginalEventID: mint.ID, Evidence: evidence,
	}
	recoveryID := pkiSecretRecoveryEventID(tenantID, mint.ID)
	if prior, found, err := s.log.EventByID(ctx, recoveryID); err != nil {
		return api.PKISecretLeafRecovery{}, err
	} else if found {
		var recovered projections.CACertificateInventoryRecovered
		if json.Unmarshal(prior.Data, &recovered) == nil {
			out.Evidence = recovered.Evidence
		}
		out.AlreadyRecovered = true
		return out, nil
	}
	if existing, err := s.store.GetCertificateByFingerprint(ctx, tenantID, info.SHA256Fingerprint); err == nil {
		return api.PKISecretLeafRecovery{}, fmt.Errorf("%w: as %s", api.ErrPKISecretLeafInInventory, existing.ID)
	} else if !store.IsNotFound(err) {
		return api.PKISecretLeafRecovery{}, err
	}
	if err := s.appendPKISecretRecovery(ctx, tenantID, mint.ID, recoveryID, IssuingCAID(), info.SerialNumber,
		info.SHA256Fingerprint, der, s.caCertDER, evidence); err != nil {
		return api.PKISecretLeafRecovery{}, err
	}
	return out, nil
}

// pkiSecretMintForSerial finds the PKI-secret mint of serial under the
// issuing CA in the tenant's retained history.
func (s *Server) pkiSecretMintForSerial(ctx context.Context, tenantID, serial string) (events.Event, projections.CAIssuedCertificate, bool, error) {
	var (
		mint   events.Event
		issued projections.CAIssuedCertificate
		found  bool
	)
	issuingCAID := IssuingCAID()
	err := s.log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		head, err := s.log.LastSequence(readCtx)
		if err != nil || head == 0 {
			return err
		}
		return s.log.ReplayTenantTypesThrough(readCtx, tenantID, 1, head, []string{projections.EventCAIssuedCertificate}, func(e events.Event) error {
			if found {
				return nil
			}
			var fact projections.CAIssuedCertificate
			if err := json.Unmarshal(e.Data, &fact); err != nil {
				return fmt.Errorf("server: decode PKI secret mint %s: %w", e.ID, err)
			}
			if fact.Source == "pkisecret" && fact.CAID == issuingCAID && fact.Serial == serial {
				mint, issued, found = e, fact, true
			}
			return nil
		})
	})
	return mint, issued, found, err
}
