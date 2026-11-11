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
	// "aws-kms" (also "aws"), "gcp-kms" (also "gcp") or "azure-key-vault"
	// (also "azure", "azure-kv"; A168-L1).
	Provider string
}

type storeManagedKeySource struct {
	store     *corestore.Store
	providers map[string]bool
	// keyID turns the record's key reference into the identity the provider's
	// source asserts.
	keyID func(string) string
	now   func() time.Time
}

var _ reducers.CloudKMSInventorySource = (*storeManagedKeySource)(nil)

func newStoreManagedKeySource(store *corestore.Store, cfg ManagedKeyAuthorityConfig) (*storeManagedKeySource, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case "aws", "aws-kms":
		return &storeManagedKeySource{store: store, providers: map[string]bool{"aws": true, "aws-kms": true}, keyID: awsManagedKeyID, now: time.Now}, nil
	case "gcp", "gcp-kms":
		// A168-L1: a Cloud KMS key version's resource name is its identity on
		// both sides.
		return &storeManagedKeySource{store: store, providers: map[string]bool{"gcp": true, "gcp-kms": true}, keyID: strings.TrimSpace, now: time.Now}, nil
	case "azure", "azure-kv", "azure-key-vault":
		return &storeManagedKeySource{store: store, providers: map[string]bool{"azure": true, "azure-kv": true, "azure-key-vault": true},
			keyID: azureManagedKeyID, now: time.Now}, nil
	default:
		return nil, fmt.Errorf("xrec managed-key authority %q: provider %q is not served; use aws-kms, gcp-kms or azure-key-vault", cfg.AuthorityID, cfg.Provider)
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
			keyID := s.keyID(key.KeyID)
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

// awsManagedKeyID: an ARN names the same key as its KeyId.
func awsManagedKeyID(keyID string) string {
	if i := strings.LastIndex(keyID, "/"); i >= 0 {
		return keyID[i+1:]
	}
	return keyID
}

// azureManagedKeyID: the record holds the version's URL in its vault; the
// source asserts it relative to the vault, "keys/{name}/{version}".
func azureManagedKeyID(keyID string) string {
	if i := strings.Index(keyID, "/keys/"); i >= 0 {
		return keyID[i+1:]
	}
	return keyID
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
