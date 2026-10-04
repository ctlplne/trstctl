// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"os"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
)

func TestAuditRetentionScopeElectsPerScopeWithoutBlockingProviderBarrier(t *testing.T) {
	ctx := t.Context()
	dsn := os.Getenv("TRSTCTL_STORE_TEST_DSN")
	if dsn == "" {
		t.Fatal("real PostgreSQL fixture DSN was not provided by TestMain")
	}
	first, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(first.Close)
	if err := first.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	second, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(second.Close)
	const scope = "11111111-1111-1111-1111-111111111111"
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- first.WithAuditRetentionScope(ctx, scope, func(ctx context.Context) error {
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("first retention scope exited before entering: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("first retention scope did not enter")
	}
	// The second replica may retain a different scope, and the shared privacy
	// barrier needed by Provider quota/metering must still be acquirable.
	otherCtx, cancelOther := context.WithTimeout(ctx, time.Second)
	defer cancelOther()
	if err := second.WithAuditRetentionScope(otherCtx, "22222222-2222-2222-2222-222222222222", func(context.Context) error { return nil }); err != nil {
		t.Fatalf("other tenant blocked by retention: %v", err)
	}
	if err := second.WithPrivacyReadModelReplacementBarrier(otherCtx,
		func(context.Context) error { return nil }); err != nil {
		t.Fatalf("provider privacy barrier blocked by retention: %v", err)
	}
	backupCtx, cancelBackup := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancelBackup()
	if err := NewHistoryRewriteCoordinator(second).WithRewriteOperation(backupCtx,
		func(context.Context) error {
			t.Error("exclusive backup/rewrite operation entered during retention")
			return nil
		}); err == nil {
		t.Fatal("retention did not fence exclusive backup/rewrite operation")
	}
	competingCtx, cancelCompeting := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancelCompeting()
	if err := second.WithAuditRetentionScope(competingCtx, scope, func(context.Context) error {
		t.Error("second replica entered the same retention scope")
		return nil
	}); err == nil {
		t.Fatal("second replica did not wait for same-scope archiver")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := second.WithAuditRetentionScope(ctx, scope, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("same-scope archiver did not resume after release: %v", err)
	}
	if err := second.WithAuditRetentionScope(ctx, events.LegacyProviderGlobalAuditScope,
		func(context.Context) error { return nil }); err != nil {
		t.Fatalf("historical Provider audit partition was refused: %v", err)
	}
	if err := second.WithAuditRetentionScope(ctx, events.LegacyProviderGlobalAuditScope+"-unknown",
		func(context.Context) error { return nil }); err == nil {
		t.Fatal("unknown textual event partition entered retention")
	}
}
