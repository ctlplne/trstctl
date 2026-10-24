// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Historical PKI-secret leaves (A111). Before ca.certificate.issued v3, a
// PKI-secret mint projected only its responder serial: v2 retained the public
// leaf, v1 only the serial. Neither had an inventory row, so the inventory
// revocation workflow could not reach the leaf. The control plane recovers a
// v2 leaf from its own retained evidence, after checking it against the
// issuing CA's certificate this process holds; the projector checks the same
// facts again. Custody stays unknown, and a leaf this CA did not sign is left
// as serial evidence.

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
	event  events.Event
	issued projections.CAIssuedCertificate
}

// recoverLegacyPKISecretInventory recovers every retained v2 PKI-secret leaf
// the issuing CA signed that has no inventory row yet. A retry converges: each
// original mint has one deterministic recovery event.
func (s *Server) recoverLegacyPKISecretInventory(ctx context.Context) (pkiSecretRecovery, error) {
	var out pkiSecretRecovery
	if s.log == nil || s.store == nil || len(s.caCertDER) == 0 {
		return out, nil
	}
	issuingCAID := IssuingCAID()
	var candidates []pkiSecretRecoveryCandidate
	err := s.log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		head, err := s.log.LastSequence(readCtx)
		if err != nil || head == 0 {
			return err
		}
		return s.log.ReplayTypesThrough(readCtx, 1, head, []string{projections.EventCAIssuedCertificate}, func(e events.Event) error {
			if e.SchemaVersion != projections.CAIssuedCertificateEvidenceSchemaVersion {
				return nil
			}
			var issued projections.CAIssuedCertificate
			if err := json.Unmarshal(e.Data, &issued); err != nil {
				return fmt.Errorf("server: decode PKI secret mint %s: %w", e.ID, err)
			}
			if issued.Source != "pkisecret" || len(issued.CertificateDER) == 0 {
				return nil
			}
			candidates = append(candidates, pkiSecretRecoveryCandidate{event: e, issued: issued})
			return nil
		})
	})
	if err != nil {
		return out, err
	}
	for _, c := range candidates {
		info, err := certinfo.Inspect(c.issued.CertificateDER)
		if err != nil || c.issued.CAID != issuingCAID || info.IsCA || info.SerialNumber != c.issued.Serial ||
			info.SHA256Fingerprint != c.issued.Fingerprint || crypto.VerifyLeafSignedByCA(c.issued.CertificateDER, s.caCertDER) != nil {
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
			// An operator already holds this leaf in inventory (an import, say);
			// recovery adds no second row and does not change that one.
			out.InInventory++
			continue
		} else if !store.IsNotFound(err) {
			return out, err
		}
		if err := s.appendPKISecretRecovery(ctx, c.event.TenantID, c.event.ID, recoveryID, c.issued.CAID, c.issued.Serial,
			c.issued.Fingerprint, c.issued.CertificateDER, projections.RecoveredFromRetainedLeaf); err != nil {
			return out, err
		}
		out.Recovered++
	}
	return out, nil
}

func (s *Server) appendPKISecretRecovery(ctx context.Context, tenantID, originalEventID, recoveryID, caID, serial, fingerprint string, der []byte, evidence string) error {
	payload, err := json.Marshal(projections.CACertificateInventoryRecovered{
		OriginalEventID: originalEventID, CAID: caID, Serial: serial, Fingerprint: fingerprint,
		CertificateDER: der, IssuerCertificateDER: s.caCertDER, Evidence: evidence, RecoveredAt: time.Now().UTC(),
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
