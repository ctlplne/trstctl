// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/inputtext"
	"trstctl.com/trstctl/internal/store"
)

// tenantPoisonQuarantine caches positive durable lookups during an ordered
// replay. A healthy answer is checked again on the next event, because a peer
// projector may quarantine that tenant between events. Only a
// known, deterministic text encoding failure is quarantined; transport, custody,
// and unknown projection errors still stop replay instead of being hidden.
type tenantPoisonQuarantine struct {
	store *store.Store
	known map[string]bool
}

func newTenantPoisonQuarantine(st *store.Store) *tenantPoisonQuarantine {
	return &tenantPoisonQuarantine{store: st, known: make(map[string]bool)}
}

func (q *tenantPoisonQuarantine) skip(ctx context.Context, e events.Event) (bool, error) {
	// Historical Provider audit has a textual pre-UUID partition. It is not a
	// customer tenant and must keep its existing replay path. There is no
	// tenant-scoped quarantine row to write for this legacy scope.
	if events.IsLegacyProviderGlobalAudit(e) {
		return false, events.ValidateEventText(e)
	}
	quarantined, seen := q.known[e.TenantID]
	if !seen {
		var err error
		quarantined, err = q.store.ProjectionTenantQuarantined(ctx, e.TenantID)
		if err != nil {
			return false, err
		}
		if quarantined {
			q.known[e.TenantID] = true
		}
	}
	if quarantined {
		// A tenant's served read model is unavailable, but erasure, key
		// destruction, and other custody changes still need replay. If one
		// cannot be projected safely, stop instead of pretending it ran.
		if isKeyStateMutationEventType(e.Type) {
			return false, events.ValidateEventText(e)
		}
		return true, nil
	}
	textErr := events.ValidateEventText(e)
	if textErr == nil {
		return false, nil
	}
	if isKeyStateMutationEventType(e.Type) {
		return false, fmt.Errorf("projections: key-state event %d cannot be quarantined: %w", e.Sequence, textErr)
	}
	reasonCode := ""
	switch {
	case errors.Is(textErr, inputtext.ErrNUL):
		reasonCode = "nul_text"
	case errors.Is(textErr, inputtext.ErrInvalidUTF8):
		reasonCode = "invalid_utf8"
	default:
		return false, textErr
	}
	if err := q.store.RecordProjectionTenantQuarantine(ctx, e.TenantID, e.Sequence, reasonCode); err != nil {
		return false, err
	}
	q.known[e.TenantID] = true
	return true, nil
}
