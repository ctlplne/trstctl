// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/store"
)

func TestCR143ReservedProviderAuthorityHasItsOwnEventProtectionFence(t *testing.T) {
	s := newStore(t)
	entered := false
	if err := s.WithTenantEventProtection(t.Context(), store.ZeroUUID, func(context.Context) error {
		entered = true
		return nil
	}); err != nil || !entered {
		t.Fatalf("reserved Provider fence: entered=%v err=%v", entered, err)
	}
	if err := s.WithKeyLock(t.Context(), eventprotect.KeyRef{TenantID: store.ZeroUUID,
		ID: "22222222-2222-4222-8222-222222222222"}, func(context.Context) error {
		t.Fatal("the Provider authority partition reached key custody")
		return nil
	}); err == nil {
		t.Fatal("a reserved Provider authority partition was accepted for key custody")
	}
}
