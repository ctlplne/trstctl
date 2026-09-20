// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"net/url"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// TestHistoryAwareLogNestedReplayUsesOneStoreConnection is the production
// composition proof behind event-only backup. The outer export view and Replay's
// inner view must use the exact coordinator configured on Log; otherwise a
// one-connection pool waits on itself forever. A concurrent cutover must remain
// outside that complete view.
func TestHistoryAwareLogNestedReplayUsesOneStoreConnection(t *testing.T) {
	type historyAssemblyFixture struct {
		Fixture bool `json:"fixture"`
	}
	if err := events.RegisterPrivacyEventPolicy("history.assembly.fixture", events.DefaultSchemaVersion, events.PrivacyEventPolicy{
		PayloadShape:      events.PrivacyPayloadShapeOf[historyAssemblyFixture](),
		RejectSubjectData: true,
	}); err != nil {
		t.Fatalf("register history assembly fixture privacy policy: %v", err)
	}
	dsn, err := url.Parse(serverTestPostgresDSN(t))
	if err != nil {
		t.Fatalf("parse test DSN: %v", err)
	}
	query := dsn.Query()
	query.Set("pool_max_conns", "1")
	dsn.RawQuery = query.Encode()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := store.Open(ctx, dsn.String())
	if err != nil {
		t.Fatalf("open one-connection store: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate one-connection store: %v", err)
	}
	key, err := jose.GenerateRSASigningKey("history-assembly-test")
	if err != nil {
		t.Fatal(err)
	}
	log, err := openHistoryAwareEventLog(
		ctx,
		config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()},
		st,
		key,
	)
	if err != nil {
		t.Fatalf("open history-aware log: %v", err)
	}
	defer func() { _ = log.Close() }()
	if _, err := log.Append(ctx, events.Event{
		Type:     "history.assembly.fixture",
		TenantID: "22bdcaa0-7286-4c85-a318-81871274ebd6",
		Data:     []byte(`{"fixture":true}`),
	}); err != nil {
		t.Fatalf("append fixture: %v", err)
	}

	readEntered := make(chan struct{})
	releaseRead := make(chan struct{})
	readDone := make(chan error, 1)
	go func() {
		readDone <- log.WithHistoryRead(ctx, func(readCtx context.Context) error {
			var records int
			if err := log.Replay(readCtx, 0, func(events.Event) error {
				records++
				return nil
			}); err != nil {
				return err
			}
			if records != 1 {
				t.Errorf("replayed records = %d, want 1", records)
			}
			close(readEntered)
			select {
			case <-releaseRead:
				return nil
			case <-readCtx.Done():
				return context.Cause(readCtx)
			}
		})
	}()
	select {
	case <-readEntered:
	case <-ctx.Done():
		t.Fatal("nested Replay deadlocked while the one available store connection held the outer read view")
	}

	cutoverStarted := make(chan struct{})
	cutoverDone := make(chan error, 1)
	go func() {
		close(cutoverStarted)
		cutoverDone <- store.NewHistoryRewriteCoordinator(st).WithCutover(ctx, func(context.Context) error {
			return nil
		})
	}()
	<-cutoverStarted
	select {
	case err := <-cutoverDone:
		t.Fatalf("cutover crossed an active complete export view: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	close(releaseRead)
	if err := <-readDone; err != nil {
		t.Fatalf("complete export read view: %v", err)
	}
	if err := <-cutoverDone; err != nil {
		t.Fatalf("cutover after export view: %v", err)
	}
}
