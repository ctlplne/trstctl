// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// reconcileAppendedAuthority handles the event/SQL split after a creation
// event has been acknowledged by JetStream but the inline projection or SQL
// COMMIT failed. The event is already source truth: reporting "rolled back,
// retry" would be false and could cause a second CA creation. Confirm the
// exact projected authority and ceremony, applying the same event if the tail
// has not caught up. A failed confirmation returns an indeterminate effect so
// the HTTP idempotency claim remains fenced for operator recovery.
func (h *caHierarchyService) reconcileAppendedAuthority(
	ctx context.Context, tenantID, ceremonyID string, expected store.CAAuthority,
	appended events.Event, originalErr error,
) (store.CAAuthority, error) {
	indeterminate := func(reason error) (store.CAAuthority, error) {
		return store.CAAuthority{}, fmt.Errorf("%w: CA authority event %s was appended but exact projection could not be confirmed (transaction: %v; recovery: %v)",
			orchestrator.ErrEffectIndeterminate, appended.ID, originalErr, reason)
	}
	if appended.ID == "" || appended.TenantID != tenantID || expected.ID == "" || ceremonyID == "" {
		return indeterminate(errors.New("incomplete authority event identity"))
	}
	var payload projections.CAAuthorityCreated
	if err := json.Unmarshal(appended.Data, &payload); err != nil {
		return indeterminate(err)
	}
	if payload.CAID != expected.ID || payload.CeremonyID != ceremonyID ||
		payload.SignerHandle != expected.SignerHandle || payload.Serial != expected.Serial ||
		payload.CertificatePEM != expected.CertificatePEM || payload.Kind != expected.Kind ||
		!sameCAParent(payload.ParentID, expected.ParentID) {
		return indeterminate(errors.New("acknowledged authority event differs from reviewed mutation"))
	}
	work, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		actual, authorityErr := h.store.GetCAAuthority(work, tenantID, expected.ID)
		ceremony, ceremonyErr := h.store.GetKeyCeremony(work, tenantID, ceremonyID)
		if authorityErr == nil && ceremonyErr == nil {
			if !sameCreatedAuthority(actual, expected) || ceremony.Status != "completed" {
				return indeterminate(errors.New("projected authority or ceremony does not match acknowledged event"))
			}
			return actual, nil
		}
		if authorityErr != nil && !errors.Is(authorityErr, pgx.ErrNoRows) {
			lastErr = authorityErr
		} else if ceremonyErr != nil && !errors.Is(ceremonyErr, pgx.ErrNoRows) {
			lastErr = ceremonyErr
		} else {
			lastErr = projections.New(h.store).Apply(work, appended)
		}
		if work.Err() != nil {
			break
		}
		if lastErr != nil && !store.IsTransactionRollback(lastErr) {
			// A concurrent tail may have committed while this apply failed; one
			// final read is still required before declaring an unknown outcome.
			continue
		}
	}
	if actual, err := h.store.GetCAAuthority(work, tenantID, expected.ID); err == nil {
		if ceremony, ceremonyErr := h.store.GetKeyCeremony(work, tenantID, ceremonyID); ceremonyErr == nil &&
			ceremony.Status == "completed" && sameCreatedAuthority(actual, expected) {
			return actual, nil
		}
	}
	return indeterminate(lastErr)
}

func sameCAParent(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func sameCreatedAuthority(actual, expected store.CAAuthority) bool {
	return actual.ID == expected.ID && actual.TenantID == expected.TenantID &&
		actual.Status == "active" && actual.Kind == expected.Kind &&
		sameCAParent(actual.ParentID, expected.ParentID) &&
		actual.Serial == expected.Serial && actual.CertificatePEM == expected.CertificatePEM &&
		actual.SignerHandle == expected.SignerHandle && actual.CommonName == expected.CommonName &&
		actual.MaxPathLen == expected.MaxPathLen &&
		slices.Equal(actual.PermittedDNSNames, expected.PermittedDNSNames) &&
		slices.Equal(actual.EKUs, expected.EKUs)
}
