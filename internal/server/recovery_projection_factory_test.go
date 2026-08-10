// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/license"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type recoveryReceiptProjection struct {
	resets  int
	applied []events.Event
}

func (p *recoveryReceiptProjection) Name() string { return "test.recovery.receipt" }

func (p *recoveryReceiptProjection) Reset(context.Context) error {
	p.resets++
	p.applied = nil
	return nil
}

func (p *recoveryReceiptProjection) Apply(_ context.Context, event events.Event) error {
	p.applied = append(p.applied, event)
	return nil
}

func TestRecoveryProjectionFactoryJoinsTheActualRebuild(t *testing.T) {
	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	if _, err := log.Append(ctx, events.Event{
		ID: "licensed-recovery-receipt", Type: "licensed.recovery.receipt", TenantID: store.ZeroUUID,
	}); err != nil {
		t.Fatalf("append extension event: %v", err)
	}

	receipt := &recoveryReceiptProjection{}
	called := 0
	factory := func(
		_ context.Context,
		_ *config.Config,
		lic *license.Manager,
		gotStore *store.Store,
		gotLog *events.Log,
	) ([]projections.Option, error) {
		called++
		if lic == nil || lic.Tier() != license.TierCommunity {
			t.Fatalf("recovery factory license = %#v, want loaded Community manager", lic)
		}
		if gotStore != st || gotLog != log {
			t.Fatal("recovery factory did not receive the exact recovered stores")
		}
		return []projections.Option{projections.WithEventProjection(receipt)}, nil
	}
	options, err := recoveryProjectionOptions(ctx, config.Default(), st, log,
		[]EditionProjectionOptionsFactory{factory})
	if err != nil {
		t.Fatalf("recoveryProjectionOptions: %v", err)
	}
	if err := projections.New(st, options...).Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild with licensed extension: %v", err)
	}
	if called != 1 || receipt.resets != 1 || len(receipt.applied) != 1 ||
		receipt.applied[0].ID != "licensed-recovery-receipt" {
		t.Fatalf("factory/rebuild receipt = called %d, resets %d, events %+v", called, receipt.resets, receipt.applied)
	}
}
