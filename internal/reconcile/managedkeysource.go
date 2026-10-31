// SPDX-License-Identifier: BUSL-1.1

package reconcile

import (
	"context"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/managedkeystate"
	"trstctl.com/trstctl/internal/reconcile/canon"
	"trstctl.com/trstctl/internal/reconcile/canon/reducers"
	corestore "trstctl.com/trstctl/internal/store"
)

// Managed-key inventory authority (A168).
//
// A cloud KMS account asserts which keys it holds; this authority asserts which
// keys trstctl believes it holds there: the tenant's managed keys at one
// provider, from the managed-key read model, with the state each should have
// at the provider. A round between the two witnesses a key only one side
// holds (created outside trstctl's record, or deleted out from under it) and a
// key whose state drifted (disabled or scheduled for deletion by hand, or still
// usable after trstctl revoked it).
//
// What trstctl's record says the provider should show:
//   - active and superseded keys: usable. Rotation mints a successor and leaves
//     the predecessor enabled for verification.
//   - revoked: disabled (Revoke calls DisableKey).
//   - deletion pending (a cloud key's zeroize; older events say "zeroized"):
//     scheduled for deletion (Zeroize calls ScheduleKeyDeletion). Once
//     the provider's waiting period has certainly passed the key is gone from
//     the provider, so the authority stops asserting it then.
//
// Creation and deletion times are not asserted on either side: trstctl records
// when its operation completed, seconds after the provider created the key,
// and the canonical five-minute buckets would turn that gap into a false
// disagreement.

// managedKeyZeroizedHorizon is past the longest provider deletion window (AWS
// KMS allows up to 30 days).
const managedKeyZeroizedHorizon = 31 * 24 * time.Hour

// managedKeySourcePageSize is the managed-key read model's page limit.
const managedKeySourcePageSize = 100

// ManagedKeyAuthorityConfig names one managed-key inventory authority.
type ManagedKeyAuthorityConfig struct {
	AuthorityID string
	// Provider is the managed-key provider whose keys the authority asserts:
	// "aws-kms" (also accepted as "aws").
	Provider string
}

type storeManagedKeySource struct {
	store     *corestore.Store
	providers map[string]bool
	now       func() time.Time
}

var _ reducers.CloudKMSInventorySource = (*storeManagedKeySource)(nil)

func newStoreManagedKeySource(store *corestore.Store, cfg ManagedKeyAuthorityConfig) (*storeManagedKeySource, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case "aws", "aws-kms":
		return &storeManagedKeySource{store: store, providers: map[string]bool{"aws": true, "aws-kms": true}, now: time.Now}, nil
	default:
		return nil, fmt.Errorf("xrec managed-key authority %q: provider %q is not served; use aws-kms", cfg.AuthorityID, cfg.Provider)
	}
}

// CloudKMSSnapshot implements reducers.CloudKMSInventorySource from the
// tenant's managed-key read model (RLS scoped by the store).
func (s *storeManagedKeySource) CloudKMSSnapshot(ctx context.Context, tenantID string, _ *reducers.ObservationSandbox) (reducers.CloudKMSSnapshot, error) {
	if s == nil || s.store == nil {
		return reducers.CloudKMSSnapshot{}, reducers.ErrMissingSource
	}
	now := s.now().UTC()
	snap := reducers.CloudKMSSnapshot{Watermark: storeWatermark("managed-keys", now)}
	afterProvider, afterKeyID := "", ""
	for {
		page, err := s.store.ListManagedKeysPage(ctx, tenantID, afterProvider, afterKeyID, managedKeySourcePageSize)
		if err != nil {
			return reducers.CloudKMSSnapshot{}, fmt.Errorf("xrec managed-key source: %w", err)
		}
		for _, key := range page {
			if !s.providers[strings.ToLower(key.Provider)] {
				continue
			}
			status, asserted := managedKeyProviderStatus(key, now)
			if !asserted {
				continue
			}
			keyID := key.KeyID
			if i := strings.LastIndex(keyID, "/"); i >= 0 {
				keyID = keyID[i+1:] // an ARN names the same key as its KeyId
			}
			snap.Keys = append(snap.Keys, reducers.CloudKMSKey{
				KeyID: keyID, AlgorithmSpec: key.Algorithm, Status: status,
				NativeID: "managed-key:" + key.Provider + ":" + key.KeyID,
			})
		}
		if len(page) < managedKeySourcePageSize {
			return snap, nil
		}
		last := page[len(page)-1]
		afterProvider, afterKeyID = last.Provider, last.KeyID
	}
}

// managedKeyProviderStatus is the provider state trstctl's record implies, and
// whether the record still asserts a key the provider holds.
func managedKeyProviderStatus(key corestore.ManagedKey, now time.Time) (string, bool) {
	switch strings.ToLower(managedkeystate.PublicState(key.Provider, key.State)) {
	case "active", "superseded":
		return canon.StatusActive, true
	case "revoked":
		return canon.StatusDisabled, true
	case managedkeystate.DeletionPending:
		if now.Sub(key.UpdatedAt) > managedKeyZeroizedHorizon {
			return "", false
		}
		return canon.StatusPendingDeletion, true
	default:
		return canon.StatusUnknown, true
	}
}
