// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agentid/delegation"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/eventspec"
	corestore "trstctl.com/trstctl/internal/store"
)

// RootAnchorReader observes the isolated signer's durable public trust floor.
// Legacy SQL rows are never promoted to source events on SQL evidence alone.
type RootAnchorReader interface {
	ReadAgentRootAnchor(context.Context, string, string) ([]byte, string, error)
}

// BackfillLegacyRootAnchorEvents turns pre-event root registrations into
// immutable source facts only after exact signer readback. One-shot rebuilds
// without a signer pass nil: they refuse an old row rather than erase it or
// invent trust authority from a PostgreSQL copy.
func BackfillLegacyRootAnchorEvents(ctx context.Context, st *corestore.Store, log *events.Log, signer RootAnchorReader) error {
	return backfillLegacyRootAnchorEvents(ctx, st, log, signer, false)
}

// RecoverLegacyRootAnchorEvents is the paired signer/control-plane startup
// path. An explicit signer NotFound turns an old SQL-only row into a durable
// unprovisioned observation, never a registered authority event. Transport
// errors and mismatched signer tuples still stop startup.
func RecoverLegacyRootAnchorEvents(ctx context.Context, st *corestore.Store, log *events.Log, signer RootAnchorReader) error {
	return backfillLegacyRootAnchorEvents(ctx, st, log, signer, true)
}

func backfillLegacyRootAnchorEvents(ctx context.Context, st *corestore.Store, log *events.Log, signer RootAnchorReader, recordAbsent bool) error {
	if st == nil {
		return nil
	}
	var present bool
	//trstctl:system-query — before any tenant is known, the system pool checks only schema metadata; this reads no tenant rows and tolerates absent extension migrations.
	if err := st.SystemPool().QueryRow(ctx, `SELECT to_regclass('agent_root_anchors') IS NOT NULL`).Scan(&present); err != nil {
		return fmt.Errorf("agentid root: check legacy registry: %w", err)
	}
	if !present {
		return nil
	}
	//trstctl:system-query — cross-tenant startup inventory uses the system pool only for public legacy trust columns; each tenant_id/key tuple needs isolated-signer and canonical-event agreement before it becomes authority.
	rows, err := st.SystemPool().Query(ctx, `SELECT tenant_id::text, key_id, public_der, auth_ref FROM agent_root_anchors ORDER BY tenant_id, key_id`)
	if err != nil {
		return fmt.Errorf("agentid root: read legacy registry: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var tenantID, keyID, authRef string
		var publicDER []byte
		if err := rows.Scan(&tenantID, &keyID, &publicDER, &authRef); err != nil {
			return err
		}
		if log == nil {
			return errors.New("agentid root: event log unavailable for legacy registry")
		}
		registered, err := delegation.Encode(delegation.RootAnchorRegisteredV1{
			TenantID: tenantID, KeyID: keyID, PublicDER: publicDER, AuthRef: authRef,
		})
		if err != nil {
			return err
		}
		registered.ID = delegation.RootAnchorEventID(tenantID, keyID)
		canonical, found, err := log.EventByID(ctx, registered.ID)
		if err != nil {
			return err
		}
		if found {
			if !sameLegacyRootEvent(canonical, registered) {
				return fmt.Errorf("agentid root: canonical event disagrees with legacy tenant/key %s/%s: %w", tenantID, keyID, corestore.ErrIdempotencyConflict)
			}
			continue
		}
		unprovisioned, err := delegation.Encode(delegation.RootAnchorUnprovisionedV1{
			TenantID: tenantID, KeyID: keyID, PublicDER: publicDER, AuthRef: authRef,
			Reason: delegation.RootAnchorUnprovisionedReasonSignerAbsent,
		})
		if err != nil {
			return err
		}
		unprovisioned.ID = delegation.RootAnchorUnprovisionedEventID(tenantID, keyID)
		canonical, found, err = log.EventByID(ctx, unprovisioned.ID)
		if err != nil {
			return err
		}
		if found {
			if !sameLegacyRootEvent(canonical, unprovisioned) {
				return fmt.Errorf("agentid root: unprovisioned event disagrees with legacy tenant/key %s/%s: %w", tenantID, keyID, corestore.ErrIdempotencyConflict)
			}
			if recordAbsent && signer != nil {
				readDER, readAuthRef, readErr := signer.ReadAgentRootAnchor(ctx, tenantID, keyID)
				if readErr != nil && status.Code(readErr) == codes.NotFound {
					continue
				}
				if readErr != nil {
					return fmt.Errorf("agentid root: recheck unprovisioned signer floor %s/%s: %w", tenantID, keyID, readErr)
				}
				if !bytes.Equal(readDER, publicDER) || readAuthRef != authRef {
					return fmt.Errorf("agentid root: unprovisioned signer floor differs from tenant/key %s/%s", tenantID, keyID)
				}
				canonical, err = log.Append(ctx, registered)
				if err != nil {
					return fmt.Errorf("agentid root: record newly signer-verified legacy root: %w", err)
				}
				if !sameLegacyRootEvent(canonical, registered) {
					return fmt.Errorf("agentid root: newly verified legacy root conflicts with tenant/key %s/%s: %w", tenantID, keyID, corestore.ErrIdempotencyConflict)
				}
			}
			continue
		}
		if signer == nil {
			return fmt.Errorf("agentid root: legacy tenant/key %s/%s needs signer-verified source event before one-shot rebuild", tenantID, keyID)
		}
		readDER, readAuthRef, readErr := signer.ReadAgentRootAnchor(ctx, tenantID, keyID)
		if readErr != nil {
			if !recordAbsent || status.Code(readErr) != codes.NotFound {
				return fmt.Errorf("agentid root: legacy signer readback %s/%s: %w", tenantID, keyID, readErr)
			}
			canonical, err = log.Append(ctx, unprovisioned)
			if err != nil {
				return fmt.Errorf("agentid root: record signer-absent legacy tuple: %w", err)
			}
			if !sameLegacyRootEvent(canonical, unprovisioned) {
				return fmt.Errorf("agentid root: signer-absent event conflicts with legacy tenant/key %s/%s: %w", tenantID, keyID, corestore.ErrIdempotencyConflict)
			}
			continue
		}
		if !bytes.Equal(readDER, publicDER) || readAuthRef != authRef {
			return fmt.Errorf("agentid root: legacy signer readback differs from tenant/key %s/%s", tenantID, keyID)
		}
		canonical, err = log.Append(ctx, registered)
		if err != nil {
			return fmt.Errorf("agentid root: record signer-verified legacy root: %w", err)
		}
		if !sameLegacyRootEvent(canonical, registered) {
			return fmt.Errorf("agentid root: canonical event disagrees with legacy tenant/key %s/%s: %w", tenantID, keyID, corestore.ErrIdempotencyConflict)
		}
	}
	return rows.Err()
}

func sameLegacyRootEvent(actual, expected eventspec.Event) bool {
	return actual.ID == expected.ID && actual.TenantID == expected.TenantID &&
		actual.Type == expected.Type && actual.SchemaVersion == expected.SchemaVersion &&
		bytes.Equal(actual.Data, expected.Data)
}
