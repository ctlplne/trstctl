// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A CA command locks its one-use ceremony before publishing and projecting the
// authority event. The durable tail can start applying that same event before
// the command transaction commits. Both projectors must acquire the ceremony
// before the authority upsert, or PostgreSQL detects an ABBA deadlock and the
// HTTP caller receives a rollback response after the event has been committed.
func TestCAAuthorityProjectionFollowsCeremonyThenAuthorityLockOrder(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ceremonyID, err := s.CreateKeyCeremony(ctx, tenantA, "root", "opener", 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	authority := store.CAAuthority{
		ID: "53c6460a-1545-4415-ae16-d1222f49d207", TenantID: tenantA,
		CommonName: "Lock order CA", Kind: "root", Status: "active",
		CertificatePEM: racePEM, SignerHandle: "ca-lock-order", Serial: "01",
		NotAfter: &now, MaxPathLen: 1, CreatedAt: now,
	}
	tailPID := make(chan int, 1)
	tailResult := make(chan error, 1)
	err = s.WithTenant(ctx, tenantA, func(command pgx.Tx) error {
		if _, err := command.Exec(ctx, `UPDATE ca_key_ceremonies SET status='completed' WHERE tenant_id=$1 AND id=$2`, tenantA, ceremonyID); err != nil {
			return err
		}
		go func() {
			tailResult <- s.WithTenant(ctx, tenantA, func(tail pgx.Tx) error {
				var pid int
				if err := tail.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
					return err
				}
				tailPID <- pid
				return s.ApplyCAAuthorityCreatedTx(ctx, tail, authority, ceremonyID, now)
			})
		}()
		var pid int
		select {
		case pid = <-tailPID:
		case err := <-tailResult:
			return fmt.Errorf("tail ended before contention: %w", err)
		case <-ctx.Done():
			return ctx.Err()
		}
		for {
			var waitType *string
			if err := s.SystemPool().QueryRow(ctx, `SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&waitType); err != nil {
				return err
			}
			if waitType != nil && *waitType == "Lock" {
				break
			}
			select {
			case err := <-tailResult:
				return fmt.Errorf("tail ended before ceremony lock contention: %w", err)
			case <-time.After(10 * time.Millisecond):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return s.ApplyCAAuthorityCreatedTx(ctx, command, authority, ceremonyID, now)
	})
	if err != nil {
		t.Fatalf("inline CA projection deadlocked with durable tail: %v", err)
	}
	if err := <-tailResult; err != nil {
		t.Fatalf("durable tail did not converge: %v", err)
	}
	authorities, err := s.ListCAAuthorities(ctx, tenantA)
	if err != nil || len(authorities) != 1 || authorities[0].ID != authority.ID {
		t.Fatalf("converged authority = %+v, err=%v", authorities, err)
	}
}
