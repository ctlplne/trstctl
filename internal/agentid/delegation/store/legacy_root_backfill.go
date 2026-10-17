// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/agentid/delegation"
	"trstctl.com/trstctl/internal/events"
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
	if st == nil {
		return nil
	}
	var present bool
	//trstctl:system-query — startup/recovery schema probe; the core server also runs before extension migrations exist in harnesses.
	if err := st.SystemPool().QueryRow(ctx, `SELECT to_regclass('agent_root_anchors') IS NOT NULL`).Scan(&present); err != nil {
		return fmt.Errorf("agentid root: check legacy registry: %w", err)
	}
	if !present {
		return nil
	}
	//trstctl:system-query — bounded startup migration inventories public legacy trust tuples across tenants; each is reconciled against the isolated signer and canonical event before projection reset.
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
		encoded, err := delegation.Encode(delegation.RootAnchorRegisteredV1{
			TenantID: tenantID, KeyID: keyID, PublicDER: publicDER, AuthRef: authRef,
		})
		if err != nil {
			return err
		}
		encoded.ID = delegation.RootAnchorEventID(tenantID, keyID)
		canonical, found, err := log.EventByID(ctx, encoded.ID)
		if err != nil {
			return err
		}
		if !found {
			if signer == nil {
				return fmt.Errorf("agentid root: legacy tenant/key %s/%s needs signer-verified source event before one-shot rebuild", tenantID, keyID)
			}
			readDER, readAuthRef, err := signer.ReadAgentRootAnchor(ctx, tenantID, keyID)
			if err != nil {
				return fmt.Errorf("agentid root: legacy signer readback %s/%s: %w", tenantID, keyID, err)
			}
			if !bytes.Equal(readDER, publicDER) || readAuthRef != authRef {
				return fmt.Errorf("agentid root: legacy signer readback differs from tenant/key %s/%s", tenantID, keyID)
			}
			canonical, err = log.Append(ctx, encoded)
			if err != nil {
				return fmt.Errorf("agentid root: record signer-verified legacy root: %w", err)
			}
		}
		if canonical.TenantID != encoded.TenantID || canonical.Type != encoded.Type ||
			canonical.SchemaVersion != encoded.SchemaVersion || !bytes.Equal(canonical.Data, encoded.Data) {
			return fmt.Errorf("agentid root: canonical event disagrees with legacy tenant/key %s/%s: %w", tenantID, keyID, corestore.ErrIdempotencyConflict)
		}
	}
	return rows.Err()
}
