// SPDX-License-Identifier: BUSL-1.1

package reconcile

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/reconcile/canon"
	corestore "trstctl.com/trstctl/internal/store"
)

// A168: the managed-key authority asserts the provider state trstctl's record
// implies, including a cloud key's legacy "zeroized" completion as a scheduled
// deletion, and stops asserting a deleted key once the provider's longest
// waiting period has certainly passed.
func TestManagedKeyProviderStatus(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		state    string
		age      time.Duration
		want     string
		asserted bool
	}{
		{"active", 0, canon.StatusActive, true},
		{"superseded", 0, canon.StatusActive, true},
		{"revoked", 0, canon.StatusDisabled, true},
		{"deletion_pending", 24 * time.Hour, canon.StatusPendingDeletion, true},
		{"zeroized", 24 * time.Hour, canon.StatusPendingDeletion, true},
		{"deletion_pending", 40 * 24 * time.Hour, "", false},
		{"surprising", 0, canon.StatusUnknown, true},
	} {
		got, asserted := managedKeyProviderStatus(corestore.ManagedKey{Provider: "aws", State: tc.state, UpdatedAt: now.Add(-tc.age)}, now)
		if got != tc.want || asserted != tc.asserted {
			t.Errorf("%s at %s = %q asserted=%v; want %q asserted=%v", tc.state, tc.age, got, asserted, tc.want, tc.asserted)
		}
	}
	if _, err := newStoreManagedKeySource(nil, ManagedKeyAuthorityConfig{AuthorityID: "m", Provider: "gcp-kms"}); err == nil {
		t.Fatal("a provider the authority cannot assert was accepted")
	}
}
