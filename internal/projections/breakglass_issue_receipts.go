// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/breakglass"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

type onlineBreakglassIssueEvent struct {
	RequestID     string            `json:"request_id"`
	Subject       string            `json:"subject"`
	CeremonyID    string            `json:"ceremony_id"`
	RequestDigest string            `json:"request_digest"`
	Bundle        breakglass.Bundle `json:"bundle"`
}

func breakglassIssueReceiptFromEvent(e events.Event) (store.BreakglassIssueReceipt, bool, error) {
	var payload onlineBreakglassIssueEvent
	if err := json.Unmarshal(e.Data, &payload); err != nil {
		return store.BreakglassIssueReceipt{}, false, fmt.Errorf("projections: decode break-glass issue: %w", err)
	}
	if payload.CeremonyID == "" {
		if len(payload.Bundle.CertDER) != 0 || len(payload.Bundle.Signature) != 0 {
			return store.BreakglassIssueReceipt{}, false, errors.New("projections: signed online break-glass event has no ceremony")
		}
		return store.BreakglassIssueReceipt{}, false, nil // offline audit event
	}
	b := payload.Bundle
	if payload.RequestID == "" || payload.Subject == "" || payload.RequestDigest == "" ||
		b.RequestID != payload.RequestID || b.Subject != payload.Subject || len(b.CertDER) == 0 ||
		len(b.Signature) == 0 || b.IssuedAt.IsZero() || len(b.Approvals) == 0 {
		return store.BreakglassIssueReceipt{}, false, errors.New("projections: incomplete online break-glass issue event")
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return store.BreakglassIssueReceipt{}, false, err
	}
	return store.BreakglassIssueReceipt{
		TenantID: e.TenantID, CeremonyID: payload.CeremonyID, RequestID: payload.RequestID,
		Subject: payload.Subject, RequestDigest: payload.RequestDigest, Bundle: raw,
		EventSequence: e.Sequence, IssuedAt: b.IssuedAt,
	}, true, nil
}

// Warm upgrades use the event-type subject index, never an unbounded request
// lookup. The marker advances only after every receipt in the finite cut exists.
func (p *Projector) backfillBreakglassIssueReceipts(ctx context.Context, log *events.Log, through uint64) error {
	checked, err := p.store.BreakglassIssueRecoveryCursor(ctx)
	if err != nil {
		return err
	}
	if checked > through {
		return fmt.Errorf("projections: break-glass recovery cursor %d exceeds head %d", checked, through)
	}
	if checked == through {
		return nil
	}
	err = log.ReplayTypesThrough(ctx, checked+1, through, []string{EventBreakglassIssued}, func(e events.Event) error {
		rec, online, err := breakglassIssueReceiptFromEvent(e)
		if err != nil || !online {
			return err
		}
		// Tenant offboarding removes the read model. A warm backfill must not
		// resurrect an offboarded tenant's public emergency certificate.
		if _, err := p.store.GetTenant(ctx, e.TenantID); errors.Is(err, pgx.ErrNoRows) {
			return nil
		} else if err != nil {
			return err
		}
		return p.store.WithTenantProjection(ctx, e.TenantID, func(tx pgx.Tx) error {
			return p.store.ApplyBreakglassIssueReceiptTx(ctx, tx, rec)
		})
	})
	if err != nil {
		return err
	}
	return p.store.MarkBreakglassIssueCheckedThrough(ctx, through)
}
