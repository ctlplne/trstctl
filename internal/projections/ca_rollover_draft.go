// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// EventCARolloverDrafted records the re-key ceremony the CA calendar opened
// for an authority entering the configured rollover band, or why it could not
// open one (A216). Drafting changes no authority: custodians approve the
// ceremony and a person executes the re-key.
const EventCARolloverDrafted = "ca.rollover.drafted"

// CARolloverDrafted is one drafted rollover.
type CARolloverDrafted struct {
	AuthorityID        string    `json:"authority_id"`
	BandMonths         int       `json:"band_months"`
	NotAfter           time.Time `json:"not_after"`
	CeremonyID         string    `json:"ceremony_id,omitempty"`
	PreviewFingerprint string    `json:"preview_fingerprint,omitempty"`
	Reason             string    `json:"reason,omitempty"`
	TTLSeconds         int64     `json:"ttl_seconds,omitempty"`
	NotDraftedReason   string    `json:"not_drafted_reason,omitempty"`
}

// ValidateCARolloverDrafted accepts either an opened ceremony with the plan it
// binds, or the reason none was opened — never both, never neither.
func ValidateCARolloverDrafted(pl CARolloverDrafted) error {
	if !canonicalUUID(pl.AuthorityID) || pl.BandMonths < 0 || pl.BandMonths > 36 || pl.NotAfter.IsZero() {
		return errors.New("a rollover draft names its authority, band and expiry")
	}
	if pl.CeremonyID == "" {
		if pl.NotDraftedReason == "" {
			return errors.New("a rollover draft without a ceremony says why")
		}
		return nil
	}
	if pl.NotDraftedReason != "" || !canonicalUUID(pl.CeremonyID) || !lowerSHA256.MatchString(pl.PreviewFingerprint) ||
		pl.Reason == "" || pl.TTLSeconds <= 0 {
		return errors.New("a drafted ceremony names the ceremony, its reviewed plan, reason and lifetime")
	}
	return nil
}

func (p *Projector) applyCARolloverDraftedTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	if e.Type != EventCARolloverDrafted {
		return false, nil
	}
	var pl CARolloverDrafted
	if err := decode(e, &pl); err != nil {
		return true, err
	}
	if err := ValidateCARolloverDrafted(pl); err != nil {
		return true, fmt.Errorf("projections: %s: %w", e.Type, err)
	}
	return true, p.store.ApplyCARolloverDraftedTx(ctx, tx, store.CARolloverDraft{
		TenantID: e.TenantID, AuthorityID: pl.AuthorityID, BandMonths: pl.BandMonths, NotAfter: pl.NotAfter.UTC(),
		CeremonyID: pl.CeremonyID, PreviewFingerprint: pl.PreviewFingerprint, Reason: pl.Reason,
		TTLSeconds: pl.TTLSeconds, NotDraftedReason: pl.NotDraftedReason, DraftedAt: e.Time, EventSequence: e.Sequence,
	})
}
