// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"strings"

	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// This pass is bounded by the same retained history cut as startup catch-up.
// Missing source events leave NULL summaries and an unverifiable recount. Do
// not rebuild or erase the rest of the product merely to backfill invoice facts.
func (p *Projector) backfillCertificateIssuanceReceipts(ctx context.Context, log *events.Log, through uint64) error {
	needed, err := p.store.CertificateIssuanceReceiptsNeedBackfill(ctx)
	if err != nil || !needed {
		return err
	}
	return log.ReplayThrough(ctx, 0, through, func(e events.Event) error {
		dependent, err := CertificateMetadataEvent(e)
		if err != nil {
			return err
		}
		if !dependent && e.Type != EventCAEndEntityIssued && e.Type != EventCAIssuedCertificate {
			return nil
		}
		return p.store.BackfillCertificateIssuanceReceipt(ctx, e, func() (store.CertificateIssuanceReceipt, error) {
			return certificateIssuanceReceipt(e)
		})
	})
}

// A successful managed-leaf mint is an immutable certificate recording, not an
// identity's initial state transition. Re-observation and revocation do not
// create mints. Public DER binds the fingerprint; no private key is inspected.
func certificateIssuanceReceipt(e events.Event) (store.CertificateIssuanceReceipt, error) {
	summary := store.CertificateIssuanceReceipt{Status: "not_mint"}
	if e.Type == EventCAIssuedCertificate ||
		(e.Type == EventCAEndEntityIssued && schemaVersionOf(e) != CAEndEntityInventorySchemaVersion) {
		summary.Status = "unverifiable"
		if schemaVersionOf(e) != CAIssuedCertificateEvidenceSchemaVersion {
			return summary, nil
		}
		var issued CAIssuedCertificate
		if err := decode(e, &issued); err != nil {
			return summary, err
		}
		if issued.CAID == "" || issued.Serial == "" || e.Time.IsZero() || len(issued.CertificateDER) == 0 {
			return summary, nil
		}
		info, err := certinfo.Inspect(issued.CertificateDER)
		if err != nil || info.SHA256Fingerprint != issued.Fingerprint || info.SerialNumber != issued.Serial {
			return summary, nil
		}
		if info.IsCA {
			return store.CertificateIssuanceReceipt{Status: "not_mint"}, nil
		}
		summary.Status, summary.Fingerprint, summary.Time = "mint", &issued.Fingerprint, &e.Time
		return summary, nil
	}
	material, recording, err := CertificateRecordingMaterial(e)
	if err != nil || !recording {
		return summary, err
	}
	if material.ObservationOnly {
		return summary, nil
	}
	source := material.Source
	if source != "issued" && source != "edge-delegation" &&
		!strings.HasPrefix(source, "protocol:") && !strings.HasPrefix(source, "attested:") &&
		!strings.HasPrefix(source, "broker:") && !strings.HasPrefix(source, "ephemeral:") &&
		!strings.HasPrefix(source, "external-ca:") {
		return summary, nil
	}
	summary.Status = "unverifiable"
	if e.Time.IsZero() || material.Fingerprint == "" || len(material.CertificateDER) == 0 {
		return summary, nil
	}
	info, err := certinfo.Inspect(material.CertificateDER)
	if err != nil || info.SHA256Fingerprint != material.Fingerprint {
		return summary, nil
	}
	if info.IsCA {
		return store.CertificateIssuanceReceipt{Status: "not_mint"}, nil
	}
	summary.Status, summary.Fingerprint, summary.Time = "mint", &material.Fingerprint, &e.Time
	return summary, nil
}
