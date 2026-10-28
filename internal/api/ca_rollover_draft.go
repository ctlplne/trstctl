// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"time"
)

// caRolloverDraft is the re-key ceremony the CA calendar drafted for an
// authority entering the configured rollover band (A216), with the plan a
// person executes once custodians approve, or why none could be opened.
type caRolloverDraft struct {
	BandMonths         int       `json:"band_months"`
	NotAfter           time.Time `json:"not_after"`
	CeremonyID         string    `json:"ceremony_id,omitempty"`
	CeremonyStatus     string    `json:"ceremony_status,omitempty"`
	Approvals          int       `json:"approvals"`
	Threshold          int       `json:"threshold"`
	PreviewFingerprint string    `json:"preview_fingerprint,omitempty"`
	Reason             string    `json:"reason,omitempty"`
	TTLSeconds         int64     `json:"ttl_seconds,omitempty"`
	NotDraftedReason   string    `json:"not_drafted_reason,omitempty"`
	DraftedAt          time.Time `json:"drafted_at"`
}

// attachRolloverDrafts adds each authority's drafted rollover, read with the
// state of the ceremony it opened.
func (a *API) attachRolloverDrafts(ctx context.Context, tenantID string, out []caAuthorityResponse) error {
	if a.store == nil {
		return nil
	}
	drafts, err := a.store.CARolloverDrafts(ctx, tenantID)
	if err != nil || len(drafts) == 0 {
		return err
	}
	for i := range out {
		d, ok := drafts[out[i].ID]
		if !ok {
			continue
		}
		draft := &caRolloverDraft{BandMonths: d.BandMonths, NotAfter: d.NotAfter.UTC(), CeremonyID: d.CeremonyID,
			PreviewFingerprint: d.PreviewFingerprint, Reason: d.Reason, TTLSeconds: d.TTLSeconds,
			NotDraftedReason: d.NotDraftedReason, DraftedAt: d.DraftedAt.UTC()}
		if d.CeremonyID != "" {
			ceremony, err := a.store.GetKeyCeremony(ctx, tenantID, d.CeremonyID)
			if err != nil {
				return err
			}
			draft.CeremonyStatus, draft.Approvals, draft.Threshold = ceremony.Status, ceremony.Approvals, ceremony.Threshold
		}
		out[i].RolloverDraft = draft
	}
	return nil
}
