// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
)

// StagePreappendTx applies the core projection in a transaction that must
// publish the exact event before it commits. The staged receipt lets the
// command path and ordered replay recognize that committed projection.
func (p *Projector) StagePreappendTx(ctx context.Context, tx pgx.Tx, candidate events.Event) error {
	if p == nil || tx == nil || candidate.ID == "" || candidate.Sequence == 0 || candidate.Time.IsZero() {
		return errors.New("projections: incomplete staged event")
	}
	if events.SealedBearingEvent(candidate) {
		return errors.New("projections: protected event requires a keyed staged receipt")
	}
	if err := p.ApplyTx(context.WithValue(ctx, preappendPreviewContextKey{}, true), tx, candidate); err != nil {
		return err
	}
	digest, err := stagedProjectionEventDigest(candidate)
	if err != nil {
		return err
	}
	defer secret.Wipe(digest)
	return p.store.RecordStagedProjectionEventReceiptTx(ctx, tx,
		candidate.TenantID, candidate.ID, candidate.Sequence, digest)
}

// This digest binds the projection's readable event fields. Source protection
// changes the stored envelope, not the event that the projector receives.
func stagedProjectionEventDigest(event events.Event) ([]byte, error) {
	wire, err := json.Marshal(struct {
		ID, Type, TenantID string
		Sequence           uint64
		Time               int64
		SchemaVersion      int
		Data               []byte
		Actor              *events.Actor
	}{event.ID, event.Type, event.TenantID, event.Sequence, event.Time.UnixNano(),
		event.SchemaVersion, event.Data, event.Actor})
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(wire)
	return crypto.SHA256Sum(wire), nil
}
