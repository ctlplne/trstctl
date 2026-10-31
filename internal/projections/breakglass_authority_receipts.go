// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

type authorityRotationEvent struct {
	PreviousSignerHandle   string   `json:"previous_signer_handle"`
	ActiveSignerHandle     string   `json:"active_signer_handle"`
	PreviousCertificateDER []byte   `json:"previous_certificate_der"`
	ActiveCertificateDER   []byte   `json:"active_certificate_der"`
	NewSignedByPreviousDER []byte   `json:"new_signed_by_previous_der"`
	PreviousSignedByNewDER []byte   `json:"previous_signed_by_new_der"`
	CeremonyID             string   `json:"ceremony_id"`
	RequestDigest          string   `json:"request_digest"`
	Approvers              []string `json:"approvers"`
}

type authorityCrossSignEvent struct {
	IssuerSignerHandle   string   `json:"issuer_signer_handle"`
	IssuerCertificateDER []byte   `json:"issuer_certificate_der"`
	TargetCertificateDER []byte   `json:"target_certificate_der"`
	CrossCertificateDER  []byte   `json:"cross_certificate_der"`
	CeremonyID           string   `json:"ceremony_id"`
	RequestDigest        string   `json:"request_digest"`
	Approvers            []string `json:"approvers"`
}

func publicCertificatePEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func breakglassAuthorityReceiptFromEvent(e events.Event) (store.BreakglassAuthorityReceipt, error) {
	rec := store.BreakglassAuthorityReceipt{TenantID: e.TenantID, EventSequence: e.Sequence, CompletedAt: e.Time}
	switch e.Type {
	case EventBreakglassCARotated:
		var pl authorityRotationEvent
		if err := json.Unmarshal(e.Data, &pl); err != nil {
			return rec, err
		}
		if pl.CeremonyID == "" || pl.RequestDigest == "" || pl.PreviousSignerHandle == "" ||
			pl.ActiveSignerHandle == "" || pl.PreviousSignerHandle == pl.ActiveSignerHandle || len(pl.Approvers) < 2 {
			return rec, errors.New("projections: incomplete break-glass rotation result")
		}
		if err := crypto.VerifyCrossSignedCA(pl.PreviousCertificateDER, pl.ActiveCertificateDER, pl.NewSignedByPreviousDER); err != nil {
			return rec, fmt.Errorf("projections: invalid successor trust path: %w", err)
		}
		if err := crypto.VerifyCrossSignedCA(pl.ActiveCertificateDER, pl.PreviousCertificateDER, pl.PreviousSignedByNewDER); err != nil {
			return rec, fmt.Errorf("projections: invalid predecessor trust path: %w", err)
		}
		rec.CeremonyID, rec.Kind, rec.Subject, rec.RequestDigest = pl.CeremonyID, "rotation", pl.ActiveSignerHandle, pl.RequestDigest
		result, err := json.Marshal(map[string]string{
			"previous_signer_handle":     pl.PreviousSignerHandle,
			"active_signer_handle":       pl.ActiveSignerHandle,
			"previous_certificate_pem":   publicCertificatePEM(pl.PreviousCertificateDER),
			"active_certificate_pem":     publicCertificatePEM(pl.ActiveCertificateDER),
			"new_signed_by_previous_pem": publicCertificatePEM(pl.NewSignedByPreviousDER),
			"previous_signed_by_new_pem": publicCertificatePEM(pl.PreviousSignedByNewDER),
			"ceremony_id":                pl.CeremonyID, "request_digest": pl.RequestDigest,
		})
		if err != nil {
			return rec, err
		}
		rec.Result = result
	case EventBreakglassCACrossSigned:
		var pl authorityCrossSignEvent
		if err := json.Unmarshal(e.Data, &pl); err != nil {
			return rec, err
		}
		if pl.CeremonyID == "" || pl.RequestDigest == "" || pl.IssuerSignerHandle == "" || len(pl.Approvers) < 2 {
			return rec, errors.New("projections: incomplete break-glass cross-sign result")
		}
		if err := crypto.VerifyCrossSignedCA(pl.IssuerCertificateDER, pl.TargetCertificateDER, pl.CrossCertificateDER); err != nil {
			return rec, fmt.Errorf("projections: invalid cross-sign trust path: %w", err)
		}
		rec.CeremonyID, rec.Kind, rec.Subject, rec.RequestDigest = pl.CeremonyID, "cross_sign", crypto.SHA256Hex(pl.TargetCertificateDER), pl.RequestDigest
		result, err := json.Marshal(map[string]string{
			"issuer_signer_handle": pl.IssuerSignerHandle,
			"target_sha256":        rec.Subject,
			"certificate_pem":      publicCertificatePEM(pl.CrossCertificateDER),
			"ceremony_id":          pl.CeremonyID,
		})
		if err != nil {
			return rec, err
		}
		rec.Result = result
	default:
		return rec, fmt.Errorf("projections: %s is not a break-glass authority result", e.Type)
	}
	if e.ID != "breakglass-"+map[string]string{"rotation": "rotation-", "cross_sign": "cross-sign-"}[rec.Kind]+rec.CeremonyID ||
		e.TenantID == "" || e.Sequence == 0 || e.Time.IsZero() {
		return rec, errors.New("projections: break-glass authority event identity or source sequence is incomplete")
	}
	return rec, nil
}

// Warm upgrades visit only indexed authority event subjects through a finite
// history cut. A failed projection leaves the cursor unchanged for a retry.
func (p *Projector) backfillBreakglassAuthorityReceipts(ctx context.Context, log *events.Log, through uint64) error {
	checked, err := p.store.BreakglassAuthorityRecoveryCursor(ctx)
	if err != nil {
		return err
	}
	if checked > through {
		return fmt.Errorf("projections: authority receipt cursor %d exceeds head %d", checked, through)
	}
	if checked == through {
		return nil
	}
	err = replayProjectionTypesThrough(ctx, log, checked+1, through, []string{EventBreakglassCARotated, EventBreakglassCACrossSigned}, func(e events.Event) error {
		rec, err := breakglassAuthorityReceiptFromEvent(e)
		if err != nil {
			return err
		}
		if _, err := p.store.GetTenant(ctx, e.TenantID); errors.Is(err, pgx.ErrNoRows) {
			return nil // Do not resurrect an offboarded tenant.
		} else if err != nil {
			return err
		}
		return p.store.WithTenantProjection(ctx, e.TenantID, func(tx pgx.Tx) error {
			return p.store.ApplyBreakglassAuthorityReceiptTx(ctx, tx, rec)
		})
	})
	if err != nil {
		return err
	}
	return p.store.MarkBreakglassAuthorityCheckedThrough(ctx, through)
}
