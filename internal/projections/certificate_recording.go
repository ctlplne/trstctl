// SPDX-License-Identifier: MPL-2.0

package projections

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// CertificateRecordingMaterial enumerates both event families that currently
// update certificate public material. Command recovery and projection share this
// list so edge reconciliation cannot bypass the same fingerprint fence.
func CertificateRecordingMaterial(e events.Event) (store.Certificate, bool, error) {
	switch e.Type {
	case EventCertificateRecorded:
		var p CertificateRecorded
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return store.Certificate{}, true, err
		}
		return store.Certificate{
			Fingerprint: p.Fingerprint, ReplacesID: p.ReplacesID, Source: p.Source,
			NotBefore: p.NotBefore, NotAfter: p.NotAfter, ValidityAnchor: p.ValidityAnchor,
			CertificateDER: p.CertificateDER, CertificatePEM: p.CertificatePEM,
			IssuanceIdempotencyKey: p.IssuanceIdempotencyKey, IssuanceRequestBinding: p.IssuanceRequestBinding,
		}, true, nil
	case EventEdgeIssuanceReconciled:
		var p EdgeIssuanceReconciled
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return store.Certificate{}, true, err
		}
		return store.Certificate{
			Fingerprint: p.Fingerprint, Source: "edge-delegation",
			CertificateDER: p.CertificateDER, CertificatePEM: []byte(p.CertificatePEM),
		}, true, nil
	default:
		return store.Certificate{}, false, nil
	}
}

// ApplyTx takes the fingerprint fence before any approval row/fence lock. Both
// inline and tail projectors follow this order. An older already-projected
// recording cannot overwrite current import provenance or an immutable origin.
func (p *Projector) ApplyTx(ctx context.Context, tx pgx.Tx, e events.Event) error {
	// All existing event families enter this transaction boundary. The narrow
	// certificate trigger records their actual sequence when they touch a leaf;
	// a later ownership/privacy/migration write cannot go unnoticed by recovery.
	return p.store.WithCertificateProjectionOrderTx(ctx, tx, e.TenantID, e.Sequence, func() error {
		dependent, err := CertificateMetadataEvent(e)
		if err != nil {
			return err
		}
		if dependent {
			return p.store.WithCertificateMetadataEventTx(ctx, tx, e, func() error {
				return p.applyCertificateOrderedEventTx(ctx, tx, e)
			})
		}
		return p.applyCertificateOrderedEventTx(ctx, tx, e)
	})
}

func (p *Projector) applyCertificateOrderedEventTx(ctx context.Context, tx pgx.Tx, e events.Event) error {
	if err := ValidateSchemaVersion(e); err != nil {
		return err
	}
	material, recording, err := CertificateRecordingMaterial(e)
	if err != nil {
		return err
	}
	if !recording {
		return p.applyCoreEventTx(ctx, tx, e)
	}
	if err := p.store.LockCertificateRecordingTx(ctx, tx, e.TenantID, material.Fingerprint); err != nil {
		return err
	}
	head, err := p.store.CertificateRecordingHeadTx(ctx, tx, e.TenantID, material.Fingerprint)
	if err != nil {
		return err
	}
	if e.Sequence > 0 && head.Exists && head.Sequence == 0 {
		return store.ErrCertificateRecordingRebuildRequired
	}
	if e.Sequence > 0 && head.Sequence >= e.Sequence {
		if head.Sequence == e.Sequence && head.EventID != e.ID {
			return fmt.Errorf("%w: certificate recording sequence has different event identity", store.ErrIdempotencyConflict)
		}
		// Exact receipts already returned at the outer event boundary. Reaching
		// this legacy cursor without a receipt cannot prove which full envelope
		// executed. Rebuild it, rather than manufacture a digest from this call.
		return store.ErrCertificateRecordingRebuildRequired
	}
	// A genuine completed retry was inert at the outer receipt boundary; an
	// unapplied old recording is unsafe over later metadata.
	if err := p.store.GuardCertificateRecordingMetadataTx(ctx, tx, e.TenantID, material.Fingerprint, material.ReplacesID, e.Sequence); err != nil {
		return err
	}
	if err := p.store.ValidateCertificateIssuanceBindingTx(ctx, tx, e.TenantID, material); err != nil {
		return err
	}
	if err := p.applyCoreEventTx(ctx, tx, e); err != nil {
		return err
	}
	issued := e.Type == EventCertificateRecorded && material.Source == "issued" &&
		strings.HasPrefix(material.IssuanceIdempotencyKey, "issue:transition:") &&
		len(material.CertificateDER) > 0 && len(material.CertificatePEM) > 0
	return p.store.ApplyCertificateRecordingHeadTx(ctx, tx, e.TenantID, material.Fingerprint, e.ID, e.Sequence, issued)
}

// These events read or lock other rows before changing certificates. Admit the
// whole operation before those dependencies, including migration rollback's
// successor checks, mixed ownership batches and owner DELETE's FK checks.
// A statement trigger alone is too late for those operations. Commands that
// prelock rows before ApplyTx (revocation and migration updates) must also take
// this fence at command entry. Unrelated events keep their own domain ordering.
func CertificateMetadataEvent(e events.Event) (bool, error) {
	switch e.Type {
	case EventCertificateRecorded, EventEdgeIssuanceReconciled,
		EventCertificateCustodyAttested, EventCertificateRevoked, EventCertificateSuperseded,
		EventCertificateRevocationBatchApplied, EventMigrationRunRecorded,
		EventOwnerDeleted, EventPrivacySubjectErased, EventPrivacyRetentionEnforced,
		EventEndpointVerified:
		return true, nil
	case EventOwnershipAssigned:
		var assignment OwnershipAssigned
		if err := decode(e, &assignment); err != nil {
			return false, err
		}
		for _, inventoryID := range assignment.InventoryIDs {
			if strings.HasPrefix(inventoryID, "certificate/") {
				return true, nil
			}
		}
	}
	return false, nil
}
