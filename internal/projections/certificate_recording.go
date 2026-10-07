// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// LegacyManagedCALeafEvidence distinguishes the historical hierarchy v2
// payload from the same-version responder-only payload. Hierarchy producers
// always included a subject field, even when the CSR subject was empty. The
// responder form has no subject and must retain its serial-only semantics.
func LegacyManagedCALeafEvidence(e events.Event) (bool, error) {
	if e.Type != EventCAEndEntityIssued || schemaVersionOf(e) != CAIssuedCertificateEvidenceSchemaVersion {
		return false, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(e.Data, &fields); err != nil {
		return false, err
	}
	raw, present := fields["subject"]
	if !present {
		return false, nil
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '"' {
		return false, fmt.Errorf("projections: historical managed CA subject must be a string")
	}
	var subject string
	if err := json.Unmarshal(raw, &subject); err != nil {
		return false, err
	}
	return true, nil
}

// AuthenticatedExternalIssuer accepts only the external CA worker's exact
// deterministic certificate event and its authenticated request binding.
// Tenant-authored inventory source text alone is never issuer evidence.
func AuthenticatedExternalIssuer(e events.Event, fact CertificateRecorded) string {
	if e.Type != EventCertificateRecorded || !strings.HasPrefix(fact.Source, "external-ca:") {
		return ""
	}
	authorityID := strings.TrimPrefix(fact.Source, "external-ca:")
	if authorityID == "" || fact.IssuanceIdempotencyKey == "" || len(fact.IssuanceRequestBinding) != 64 {
		return ""
	}
	expected := uuid.NewSHA1(uuid.NameSpaceOID, []byte(e.TenantID+"\x00certificate.recorded\x00"+fact.IssuanceIdempotencyKey)).String()
	if e.ID != expected {
		return ""
	}
	return authorityID
}

// CertificateRecordingMaterial enumerates the event families that currently
// update certificate public material. Command recovery and projection share this
// list so edge reconciliation cannot bypass the same fingerprint fence.
func CertificateRecordingMaterial(e events.Event) (store.Certificate, bool, error) {
	if err := ValidateSchemaVersion(e); err != nil {
		return store.Certificate{}, false, err
	}
	switch e.Type {
	case EventCAEndEntityIssued:
		if schemaVersionOf(e) == CAIssuedCertificateEvidenceSchemaVersion {
			managed, err := LegacyManagedCALeafEvidence(e)
			if err != nil || !managed {
				return store.Certificate{}, false, err
			}
			var p CAIssuedCertificate
			if err := json.Unmarshal(e.Data, &p); err != nil {
				return store.Certificate{}, true, err
			}
			return store.Certificate{Fingerprint: p.Fingerprint, Source: "issued",
				CertificateDER: p.CertificateDER,
				CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.CertificateDER})}, true, nil
		}
		if schemaVersionOf(e) != CAEndEntityInventorySchemaVersion {
			return store.Certificate{}, false, nil
		}
		var p CAEndEntityInventoried
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return store.Certificate{}, true, err
		}
		return store.Certificate{Fingerprint: p.Fingerprint, Source: "issued",
			CertificateDER: p.CertificateDER, CertificatePEM: p.CertificatePEM}, true, nil
	case EventCertificateRecorded:
		var p CertificateRecorded
		if err := json.Unmarshal(e.Data, &p); err != nil {
			return store.Certificate{}, true, err
		}
		return store.Certificate{
			Fingerprint: p.Fingerprint, ReplacesID: p.ReplacesID, Source: p.Source, ObservationOnly: p.ObservationOnly,
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

// Version two retained a signed public leaf but no inventory identifier. Its
// derived row identity must be stable across replay and upgrade. The event ID
// belongs to the original mint; rebuilding inventory never mints another leaf.
func LegacyManagedCAInventoryID(e events.Event) string {
	return uuid.NewSHA1(uuid.NameSpaceOID,
		[]byte("managed-ca-legacy-inventory\x00"+e.TenantID+"\x00"+e.ID)).String()
}

// ApplyTx takes the fingerprint fence before any approval row/fence lock. Both
// inline and tail projectors follow this order. An older already-projected
// recording cannot overwrite current import provenance or an immutable origin.
func (p *Projector) ApplyTx(ctx context.Context, tx pgx.Tx, e events.Event) error {
	if err := ValidateSchemaVersion(e); err != nil {
		return err
	}
	// All existing event families enter this transaction boundary. The narrow
	// certificate trigger records their actual sequence when they touch a leaf;
	// a later ownership/privacy/migration write cannot go unnoticed by recovery.
	projectionTenant := e.TenantID
	if e.Type == audit.EventTypeArchived {
		var err error
		projectionTenant, err = store.AuditCheckpointRLSID(e.TenantID)
		if err != nil {
			return err
		}
	}
	return p.store.WithCertificateProjectionOrderTx(ctx, tx, projectionTenant, e.Sequence, func() error {
		managed, err := LegacyManagedCALeafEvidence(e)
		if err != nil {
			return err
		}
		if e.Type == EventCAIssuedCertificate ||
			(e.Type == EventCAEndEntityIssued && (schemaVersionOf(e) == 1 ||
				(schemaVersionOf(e) == CAIssuedCertificateEvidenceSchemaVersion && !managed))) {
			return p.store.WithResponderIssuanceReceiptTx(ctx, tx, e, func() error {
				return p.applyCoreEventTx(ctx, tx, e)
			}, func() (store.CertificateIssuanceReceipt, error) {
				return certificateIssuanceReceipt(e)
			})
		}
		dependent, err := CertificateMetadataEvent(e)
		if err != nil {
			return err
		}
		if dependent {
			return p.store.WithCertificateMetadataEventTx(ctx, tx, e, func() error {
				return p.applyCertificateOrderedEventTx(ctx, tx, e)
			}, func() (store.CertificateIssuanceReceipt, error) {
				return certificateIssuanceReceipt(e)
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
	issued := material.Source == "issued" && len(material.CertificateDER) > 0 && len(material.CertificatePEM) > 0 &&
		((e.Type == EventCertificateRecorded && strings.HasPrefix(material.IssuanceIdempotencyKey, "issue:transition:")) ||
			(e.Type == EventCAEndEntityIssued && (schemaVersionOf(e) == CAIssuedCertificateEvidenceSchemaVersion ||
				schemaVersionOf(e) == CAEndEntityInventorySchemaVersion)))
	return p.store.ApplyCertificateRecordingHeadTx(ctx, tx, e.TenantID, material.Fingerprint, e.ID, e.Sequence, issued)
}

// These events read or lock other rows before changing certificates. Admit the
// whole operation before those dependencies, including migration rollback's
// successor checks, mixed ownership batches and owner DELETE's FK checks.
// A statement trigger alone is too late for those operations. Commands that
// prelock rows before ApplyTx (revocation and migration updates) must also take
// this fence at command entry. Unrelated events keep their own domain ordering.
func CertificateMetadataEvent(e events.Event) (bool, error) {
	if err := ValidateSchemaVersion(e); err != nil {
		return false, err
	}
	switch e.Type {
	case EventCertificateRecorded, EventCAEndEntityIssued, EventEdgeIssuanceReconciled,
		EventCertificateCustodyAttested, EventCertificateRevoked, EventCertificateSuperseded,
		EventCertificateRevocationBatchApplied, EventMigrationRunRecorded,
		EventOwnerDeleted, EventPrivacySubjectErased, EventPrivacyRetentionEnforced,
		EventEndpointVerified:
		if e.Type == EventCAEndEntityIssued {
			if schemaVersionOf(e) == CAIssuedCertificateEvidenceSchemaVersion {
				return LegacyManagedCALeafEvidence(e)
			}
			return schemaVersionOf(e) == CAEndEntityInventorySchemaVersion, nil
		}
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
