// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// The direct writer and event projector derive the same secondary unique ID.
// Hold the projector's real PostgreSQL arbiter lock: an identical direct write
// must wait, while an unrelated asset remains writable. A shared backup fence
// cannot provide this exclusion.
func TestCryptoAssetDirectUpsertSharesProjectionArbiter(t *testing.T) {
	st := newStore(t)
	seedTwoTenants(t, st)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	asset := store.CryptoAsset{TenantID: tenantA, Kind: "host-config", Location: "/etc/arbiter-test", Protocol: "TLSv1", Strength: "weak"}
	ready, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- st.WithTenantProjection(ctx, tenantA, func(tx pgx.Tx) error {
			key := "upsert-arbiter\x1fcrypto_assets\x1f" + tenantA + "\x1f" + asset.Signature()
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, key); err != nil {
				return err
			}
			close(ready)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	finish := sync.OnceFunc(func() {
		close(release)
		if err := <-done; err != nil {
			t.Errorf("projection lock holder: %v", err)
		}
	})
	defer finish()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	other := asset
	other.Location += "-unrelated"
	if _, err := st.UpsertCryptoAsset(ctx, other); err != nil {
		t.Fatalf("unrelated asset blocked: %v", err)
	}
	waitCtx, stop := context.WithTimeout(ctx, 200*time.Millisecond)
	defer stop()
	if _, err := st.UpsertCryptoAsset(waitCtx, asset); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("direct upsert crossed the held projection arbiter: %v", err)
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM crypto_assets WHERE tenant_id=$1 AND signature=$2`, tenantA, asset.Signature()).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Errorf("canceled waiter inserted %d rows", count)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	finish()
	got, err := st.UpsertCryptoAsset(ctx, asset)
	if err != nil {
		t.Fatalf("upsert after projector commits: %v", err)
	}
	if want := store.StableCryptoAssetID(tenantA, asset.Signature()); got.ID != want {
		t.Fatalf("stable asset ID = %q, want %q", got.ID, want)
	}
}
