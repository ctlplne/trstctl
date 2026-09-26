// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenancy"
)

func TestTenantLifecycleCommitExcludesNewWorkAfterOuterSessionLoss(t *testing.T) {
	first := newStore(t)
	seedTwoTenants(t, first)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	second, err := store.Open(ctx, testDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := first.WithTenantServiceBarrier(ctx, tenantA, func(barrier context.Context) error {
		return first.WithTenant(barrier, tenantA, func(tx pgx.Tx) error {
			if err := first.TryTenantLifecycleCommitTx(barrier, tx, tenantA); err != nil {
				return err
			}
			var pid int32
			if err := second.SystemPool().QueryRow(ctx, `SELECT pid FROM pg_locks
				WHERE locktype='advisory' AND mode='ExclusiveLock' AND granted
				AND ((classid::bigint<<32)|objid::bigint)=hashtextextended($1,0)`, "tenant-service\x1f"+tenantA).Scan(&pid); err != nil {
				return err
			}
			var killed bool
			if err := second.SystemPool().QueryRow(ctx, `SELECT pg_terminate_backend($1,5000)`, pid).Scan(&killed); err != nil {
				return err
			}
			if !killed {
				t.Fatal("did not terminate the owned outer lifecycle session")
			}
			for range 2 {
				if _, release, err := second.BeginTenantService(ctx, tenantA); !errors.Is(err, store.ErrTenantServiceBusy) {
					if release != nil {
						release()
					}
					t.Fatalf("lost outer session admitted work during lifecycle commit: %v", err)
				}
			}
			if err := second.WithTenant(ctx, tenantA, func(other pgx.Tx) error {
				return second.TryTenantServiceAdmissionTx(ctx, other, tenantA)
			}); !errors.Is(err, store.ErrTenantServiceBusy) {
				t.Fatalf("durable remote handoff bypassed lifecycle commit: %v", err)
			}
			_, releaseOther, err := second.BeginTenantService(ctx, tenantB)
			if err != nil {
				t.Fatalf("unrelated customer was blocked: %v", err)
			}
			releaseOther()
			_, err = first.OffboardTenantTx(barrier, tx, tenantA)
			return err
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err := second.RequireLiveTenantService(ctx, tenantA); !errors.Is(err, tenancy.ErrServiceUnavailable) {
		t.Fatalf("committed erasure still admits service: %v", err)
	}
	// The transaction finished; no stale second lock may poison a future
	// registration of this UUID. Admission authority is still checked above.
	_, release, err := second.BeginTenantService(ctx, tenantA)
	if err != nil {
		t.Fatalf("completed lifecycle transaction retained its lock: %v", err)
	}
	release()
}

func TestTenantLifecycleCommitRefusesAlreadyAdmittedWork(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := t.Context()
	_, release, err := s.BeginTenantService(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := s.OffboardTenant(ctx, tenantA); !errors.Is(err, store.ErrTenantServiceBusy) {
		t.Fatalf("direct erase bypassed an admitted operation: %v", err)
	}
	if err := s.RequireLiveTenantService(ctx, tenantA); err != nil {
		t.Fatalf("refused erase changed tenant state: %v", err)
	}
	release()
	if _, err := s.OffboardTenant(ctx, tenantA); err != nil {
		t.Fatalf("erase could not recover after admitted work finished: %v", err)
	}
}
