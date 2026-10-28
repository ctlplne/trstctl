// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A205: published SPIRE JWT keys project per tenant; a replay converges, a
// later publication may only taint a key, a different key under a published
// ID is refused, and expired keys leave the list.
func TestSPIFFEUpstreamJWTKeysProjectPerTenant(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Microsecond)
	later, past := now.Add(time.Hour), now.Add(-time.Minute)
	// Key IDs no other test in this package uses: the database is shared.
	keyA := store.SPIFFEUpstreamJWTKey{TenantID: tenantA, KeyID: "a205-server-a", PublicKeyDER: []byte{0x30, 0x59, 0xa1},
		ExpiresAt: &later, PublishedBy: "spire-upstream", PublishedAt: now, UpdatedAt: now, EventSequence: 205001}
	keyB := store.SPIFFEUpstreamJWTKey{TenantID: tenantA, KeyID: "a205-server-b", PublicKeyDER: []byte{0x30, 0x59, 0xb1},
		PublishedBy: "spire-upstream", PublishedAt: now.Add(time.Second), UpdatedAt: now, EventSequence: 205002}
	expired := store.SPIFFEUpstreamJWTKey{TenantID: tenantA, KeyID: "a205-expired", PublicKeyDER: []byte{0x30, 0x59, 0xc1},
		ExpiresAt: &past, PublishedBy: "spire-upstream", PublishedAt: now, UpdatedAt: now, EventSequence: 205003}
	apply := func(k store.SPIFFEUpstreamJWTKey) error {
		return s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error { return s.ApplySPIFFEUpstreamJWTKeyPublishedTx(ctx, tx, k) })
	}
	for _, k := range []store.SPIFFEUpstreamJWTKey{keyA, keyB, expired, keyA} {
		if err := apply(k); err != nil {
			t.Fatalf("apply %s: %v", k.KeyID, err)
		}
	}
	listed, err := s.ListSPIFFEUpstreamJWTKeys(ctx, tenantA, now)
	if err != nil || len(listed) != 2 || listed[0].KeyID != "a205-server-a" || listed[1].KeyID != "a205-server-b" ||
		!bytes.Equal(listed[0].PublicKeyDER, keyA.PublicKeyDER) || listed[1].ExpiresAt != nil {
		t.Fatalf("listed = %+v, %v", listed, err)
	}
	if others, err := s.ListSPIFFEUpstreamJWTKeys(ctx, tenantB, now); err != nil || len(others) != 0 {
		t.Fatalf("tenant B sees %+v, %v", others, err)
	}

	tainted := keyA
	tainted.Tainted, tainted.EventSequence = true, 205004
	if err := apply(tainted); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetSPIFFEUpstreamJWTKey(ctx, tenantA, "a205-server-a"); err != nil || !got.Tainted || got.EventSequence != 205004 {
		t.Fatalf("after tainting = %+v, %v", got, err)
	}
	// Untainting is not a change a publication can make.
	untainted := keyA
	untainted.EventSequence = 205005
	if err := apply(untainted); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetSPIFFEUpstreamJWTKey(ctx, tenantA, "a205-server-a"); !got.Tainted {
		t.Fatal("a later publication untainted the key")
	}
	other := keyA
	other.PublicKeyDER, other.EventSequence = []byte{0x30, 0x59, 0xff}, 205006
	if err := apply(other); !errors.Is(err, store.ErrSPIFFEUpstreamJWTKeyConflict) {
		t.Fatalf("a different key under a published ID = %v", err)
	}
	if _, err := s.GetSPIFFEUpstreamJWTKey(ctx, tenantA, "a205-missing"); !store.IsNotFound(err) {
		t.Fatalf("missing key = %v", err)
	}
}
