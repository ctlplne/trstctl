// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// applyAuditAnchorTx projects audit.anchored (A147): the licensed anchoring
// worker's timestamp over a tenant's full audit chain. The event stays in the
// tenant's audit log, where the offline verifier reads it; the row serves the
// anchoring status and the anchor log.
func (p *Projector) applyAuditAnchorTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	if e.Type != auditanchor.EventTypeAnchored {
		return false, nil
	}
	var pl auditanchor.AnchoredEvent
	if err := decode(e, &pl); err != nil {
		return true, err
	}
	anchor, err := AuditAnchorRow(e, pl)
	if err != nil {
		return true, err
	}
	return true, p.store.ApplyAuditAnchorTx(ctx, tx, anchor)
}

// AuditAnchorRow validates an audit.anchored payload and returns its row.
func AuditAnchorRow(e events.Event, pl auditanchor.AnchoredEvent) (store.AuditAnchor, error) {
	token := pl.Anchor.Token
	if pl.Anchor.Kind != auditanchor.KindRFC3161 || token == nil || len(token.DER) == 0 {
		return store.AuditAnchor{}, errors.New("projections: audit.anchored carries no RFC 3161 timestamp")
	}
	if pl.ThroughSequence == 0 || pl.CadenceSeconds <= 0 || !token.Info.GenTime.Equal(pl.Anchor.AnchoredAt) {
		return store.AuditAnchor{}, fmt.Errorf("projections: audit.anchored payload is inconsistent")
	}
	return store.AuditAnchor{
		TenantID: e.TenantID, EventID: e.ID, ThroughSequence: pl.ThroughSequence, ChainHead: pl.Anchor.ChainHead,
		AnchoredAt: token.Info.GenTime.UTC(), TokenSerial: token.Info.SerialNumber,
		TokenSHA256: crypto.SHA256Hex(token.DER), CadenceSeconds: pl.CadenceSeconds,
		EventSequence: e.Sequence, RecordedAt: e.Time,
	}, nil
}
