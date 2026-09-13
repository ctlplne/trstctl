// SPDX-License-Identifier: MPL-2.0

package projections

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

const EventCertificateRevocationBatchApplied = "certificate.revocation.batch.applied"

// Version 2 adds queued external authority intents. Version 1 remains the
// immediate local-ledger contract and must never acquire new remote effects.
const CertificateExternalRevocationSchemaVersion = 2

// MaxCertificateRevocationBatch bounds row locks, policy evaluations and event
// size. Large incident plans submit explicit, independently tracked batches.
const MaxCertificateRevocationBatch = 100

const CertificateRevocationUnsupportedReason = "issuer revocation is not supported for this certificate; use its issuing CA"

// CertificateRevocationBatchApplied is a retained command receipt, not a fresh
// selector to re-run after a crash. Public certificate bytes and private keys do
// not belong in the receipt. Its targets were signature-checked before append.
type CertificateRevocationBatchApplied struct {
	RequestBinding string                      `json:"request_binding"`
	Reason         string                      `json:"reason"`
	Items          []CertificateRevocationItem `json:"items"`
}

type CertificateRevocationItem struct {
	ID           string `json:"id"`
	Matched      bool   `json:"matched"`
	Status       string `json:"status"`
	Error        string `json:"error,omitempty"`
	Fingerprint  string `json:"fingerprint,omitempty"`
	Serial       string `json:"serial,omitempty"`
	CAID         string `json:"ca_id,omitempty"`
	ExternalCAID string `json:"external_ca_id,omitempty"`
}

func ValidateCertificateRevocationBatch(batch CertificateRevocationBatchApplied) error {
	if !revocationDigest(batch.RequestBinding) || !crypto.IsValidRevocationReason(batch.Reason) || batch.Reason == "removeFromCRL" ||
		len(batch.Items) == 0 || len(batch.Items) > MaxCertificateRevocationBatch {
		return errors.New("projections: incomplete certificate revocation command")
	}
	seen := make(map[string]bool, len(batch.Items))
	for _, item := range batch.Items {
		if id, err := uuid.Parse(item.ID); err != nil || id.String() != item.ID || seen[item.ID] {
			return errors.New("projections: certificate revocation selection has an empty or duplicate id")
		}
		seen[item.ID] = true
		if item.Status != "revoked" && item.Status != "queued" && (item.CAID != "" || item.ExternalCAID != "" || item.Fingerprint != "" || item.Serial != "") {
			return errors.New("projections: inactive certificate outcome carries unexpected authority fields")
		}
		switch item.Status {
		case "queued":
			if !item.Matched || item.CAID != "" || item.ExternalCAID == "" || len(item.ExternalCAID) > 256 ||
				strings.TrimSpace(item.ExternalCAID) != item.ExternalCAID || item.Serial == "" ||
				strings.Trim(item.Serial, "0123456789abcdef") != "" || !revocationDigest(item.Fingerprint) || item.Error != "" {
				return errors.New("projections: queued external revocation has no exact authority binding")
			}
		case "revoked":
			caID, caErr := uuid.Parse(item.CAID)
			if !item.Matched || item.ExternalCAID != "" || caErr != nil || caID.String() != item.CAID || item.Serial == "" ||
				strings.Trim(item.Serial, "0123456789abcdef") != "" || !revocationDigest(item.Fingerprint) || item.Error != "" {
				return errors.New("projections: certificate revocation has no exact authority binding")
			}
		case "skipped":
			if !item.Matched || item.Error != "already revoked" {
				return errors.New("projections: invalid skipped certificate revocation")
			}
		case "failed":
			if (!item.Matched && item.Error != "not found") || (item.Matched && item.Error != CertificateRevocationUnsupportedReason) {
				return errors.New("projections: failed certificate revocation requires a closed-set reason")
			}
		default:
			return errors.New("projections: unknown certificate revocation outcome")
		}
	}
	return nil
}

func revocationDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && value == strings.ToLower(value)
}

func (p *Projector) applyCertificateRevocationBatchTx(ctx context.Context, tx pgx.Tx, event events.Event) error {
	var batch CertificateRevocationBatchApplied
	if err := decode(event, &batch); err != nil {
		return err
	}
	if err := ValidateCertificateRevocationBatch(batch); err != nil {
		return err
	}
	if event.ID == "" || event.Time.IsZero() {
		return errors.New("projections: revocation requires the canonical event identity and time")
	}
	for _, item := range batch.Items {
		if item.Status == "queued" {
			if event.SchemaVersion != CertificateExternalRevocationSchemaVersion {
				return errors.New("projections: legacy revocation cannot authorize an external effect")
			}
			if err := p.store.EnsureExternalCertificateRevocationTx(ctx, tx, event.TenantID, store.ExternalCertificateRevocation{
				EventID: event.ID, CertificateID: item.ID, Fingerprint: item.Fingerprint, Serial: item.Serial,
				ExternalCAID: item.ExternalCAID, Reason: batch.Reason,
			}); err != nil {
				return err
			}
			continue
		}
		if item.Status != "revoked" {
			continue
		}
		if err := p.store.ApplyExactCertificateRevocationTx(ctx, tx, event.TenantID,
			item.ID, item.Fingerprint, item.Serial, item.CAID, batch.Reason,
			crypto.CRLReasonCode(crypto.RevocationReason(batch.Reason)), event.Time); err != nil {
			return fmt.Errorf("projections: exact certificate revocation: %w", err)
		}
		// Both the authority state and publication intent commit in this tx.
		// Replaying a receipt repairs a missing outbox row without new selection.
		if err := p.store.EnsureCertificateCRLPublicationTx(ctx, tx, event.TenantID, event.ID, item.CAID); err != nil {
			return err
		}
	}
	return nil
}
