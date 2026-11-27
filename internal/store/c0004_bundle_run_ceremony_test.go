// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestC0004BundleRunCeremonyOwnerHasNoQuorumPower(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	seedTwoTenants(t, s)
	ceremonyID, err := s.CreateKeyCeremony(ctx, tenantA, "root", "bundle-run:c0004-owner", 1)
	if err != nil {
		t.Fatal(err)
	}
	matched, err := s.DelegatedTokenMinterMatches(ctx, tenantA, "bundle-run:c0004-owner", []string{"c0004-owner"})
	if err != nil || !matched {
		t.Fatalf("bundle run and its owner were treated as distinct: matched=%t err=%v", matched, err)
	}
	if _, _, err := s.ReserveKeyCeremonyApproval(ctx, tenantA, ceremonyID, "c0004-owner"); !errors.Is(err, store.ErrSelfApproval) {
		t.Fatalf("owner reserved an approval on their bundle run's ceremony: %v", err)
	}
	// Replay an approval accepted before this fix. It stays in history but
	// never counts toward the key ceremony's quorum after an upgrade.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyKeyCeremonyApprovedTx(ctx, tx, tenantA, ceremonyID, "c0004-owner",
			"77000000-0000-4000-8000-000000000004", 1, time.Now().UTC())
	}); err != nil {
		t.Fatal(err)
	}
	if err := consumeCeremonyForTest(t, s, ceremonyID, "root"); !errors.Is(err, store.ErrKeyCeremonyQuorumNotMet) {
		t.Fatalf("retained owner vote supplied ceremony quorum: %v", err)
	}
}
