// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// RecordScannedCertificateChainWithEventID keeps the issuer certificates a
// scan saw served with a leaf (A211), under the relay report's event id so a
// retried report cannot change them.
func (o *Orchestrator) RecordScannedCertificateChainWithEventID(ctx context.Context, tenantID, eventID string,
	chain projections.ScannedCertificateChainObserved) error {
	if o == nil || o.log == nil || strings.TrimSpace(eventID) == "" {
		return errors.New("orchestrator: a scanned chain needs an event id")
	}
	if err := projections.ValidateScannedCertificateChain(chain); err != nil {
		return fmt.Errorf("orchestrator: %w", err)
	}
	raw, err := json.Marshal(chain)
	if err != nil {
		return err
	}
	return o.withTenantCommand(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		event, err := o.log.Append(ctx, events.Event{ID: eventID, Type: projections.EventScannedCertificateChainObserved,
			TenantID: tenantID, Data: raw})
		if err != nil {
			return err
		}
		if event.ID != eventID || event.Type != projections.EventScannedCertificateChainObserved ||
			event.TenantID != tenantID || !bytes.Equal(event.Data, raw) {
			return fmt.Errorf("%w: scanned chain differs from the retained one", store.ErrIdempotencyConflict)
		}
		return o.proj.ApplyTx(ctx, tx, event)
	})
}
