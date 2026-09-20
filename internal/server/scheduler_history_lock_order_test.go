// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

type aud116HistoryLockProbe struct {
	base        events.HistoryRewriteCoordinator
	readAttempt chan struct{}
	readOnce    sync.Once
}

func (p *aud116HistoryLockProbe) WithRewriteOperation(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	return p.base.WithRewriteOperation(ctx, fn)
}

func (p *aud116HistoryLockProbe) WithCutover(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	return p.base.WithCutover(ctx, fn)
}

func (p *aud116HistoryLockProbe) WithRead(
	ctx context.Context,
	fn func(context.Context) error,
) error {
	p.readOnce.Do(func() { close(p.readAttempt) })
	return p.base.WithRead(ctx, fn)
}

func TestOrdinaryMutationCannotInvertBackupAndHistoryFencesAUD116(t *testing.T) {
	const tenantID = "11111111-1111-1111-1111-111111111111"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	st := newServerTestStore(t)
	probe := &aud116HistoryLockProbe{
		base:        store.NewHistoryRewriteCoordinator(st),
		readAttempt: make(chan struct{}),
	}
	log, err := events.Open(
		ctx,
		config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true},
		events.WithHistoryRewriteCoordinator(probe),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })

	backupShared := make(chan struct{})
	allowAppend := make(chan struct{})
	appendFinished := make(chan struct{})
	mutationDone := make(chan error, 1)
	go func() {
		mutationDone <- st.WithTenant(ctx, tenantID, func(pgx.Tx) error {
			close(backupShared)
			select {
			case <-allowAppend:
			case <-ctx.Done():
				return context.Cause(ctx)
			}
			_, err := log.Append(ctx, events.Event{
				ID: "aud116-lock-order-mutation", Type: "owner.updated",
				TenantID: tenantID, Data: []byte(`{"name":"lock-order"}`),
			})
			close(appendFinished)
			return err
		})
	}()

	select {
	case <-backupShared:
	case <-ctx.Done():
		t.Fatalf("tenant mutation did not acquire the shared backup fence: %v", context.Cause(ctx))
	}

	cutoverDone := make(chan error, 1)
	go func() {
		cutoverDone <- probe.WithCutover(ctx, func(cutoverCtx context.Context) error {
			close(allowAppend)
			// Before the correction, Append tried to take history(S) here while
			// already owning backup(S). Waiting until that attempt made the inverse
			// history(X)->backup(X) edge below deterministic. After the correction,
			// Append reaches its broker publish without taking history(S), and the
			// appendFinished branch proves the cycle is absent.
			select {
			case <-probe.readAttempt:
			case <-appendFinished:
			case <-cutoverCtx.Done():
				return context.Cause(cutoverCtx)
			}
			return st.PrepareTenantDataCutover(
				cutoverCtx,
				events.TenantDataRewriteReport{TenantID: tenantID},
				func(context.Context) error { return nil },
			)
		})
	}()

	mutationErr := <-mutationDone
	cutoverErr := <-cutoverDone
	if mutationErr != nil || cutoverErr != nil {
		t.Fatalf(
			"backup(S)->history(S) / history(X)->backup(X) cycle: mutation=%v cutover=%v",
			mutationErr, cutoverErr,
		)
	}
}
