// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"context"
	"errors"
)

// TenantMetadataByID resolves exact source identity without opening a body.
// DeclaredKeyID is untrusted routing metadata, never proof of key authority.
// A caller can inspect a prospective public control before any logical read,
// avoiding recursive key resolution if that control was incorrectly encrypted.
func (l *Log) TenantMetadataByID(ctx context.Context, tenantID, id string) (EnvelopeMetadata, bool, error) {
	if l == nil || tenantID == "" || id == "" {
		return EnvelopeMetadata{}, false, errors.New("events: metadata lookup requires log, tenant and identity")
	}
	tenantID = normalizedTenantScope(tenantID)
	var meta EnvelopeMetadata
	var found bool
	err := l.withHistoryRead(ctx, func(readCtx context.Context) error {
		event, exists, err := l.rawEventByID(readCtx, id)
		if err != nil || !exists {
			return err
		}
		if normalizedTenantScope(event.TenantID) != tenantID {
			return ErrConflictingEventIdentity
		}
		meta, found = envelopeMetadata(event), true
		return nil
	})
	if err != nil {
		return EnvelopeMetadata{}, false, err
	}
	return meta, found, nil
}
