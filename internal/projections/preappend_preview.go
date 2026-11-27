// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
)

type preappendPreviewContextKey struct{}

// PreviewTx runs the core read-model projection on a savepoint of the command's
// own tenant transaction. It always rolls back that savepoint, so a rejected
// candidate cannot reach the event log and a successful preview changes no
// read state. The ordinary apply still runs after the source append.
func (p *Projector) PreviewTx(ctx context.Context, tx pgx.Tx, candidate events.Event) error {
	if p == nil || tx == nil || candidate.ID == "" || candidate.Sequence == 0 {
		return errors.New("projections: incomplete preappend candidate")
	}
	preview, err := tx.Begin(ctx)
	if err != nil {
		return err
	}
	applyErr := p.ApplyTx(context.WithValue(ctx, preappendPreviewContextKey{}, true), preview, candidate)
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return errors.Join(applyErr, preview.Rollback(rollbackCtx))
}
