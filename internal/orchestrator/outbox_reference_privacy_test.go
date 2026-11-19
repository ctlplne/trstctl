// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"

	"trstctl.com/trstctl/internal/orchestrator"
)

func TestSecretDeliveryDebugRecordsOnlySafeErrorClass(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	var logged bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previous)
	outbox := orchestrator.NewOutbox(st, orchestrator.WithMaxAttempts(1))
	destinations := []string{
		"dynsecret.issue", "dynsecret.revoke", "secret.static-rotation", "discovery.run",
		orchestrator.DestinationResponseSplunk, orchestrator.DestinationResponseJira,
		orchestrator.DestinationScanAnnotation, orchestrator.DestinationOAuthProviderAction,
	}
	for _, destination := range destinations {
		enqueue(t, st, outbox, orchestrator.Entry{
			TenantID: tenantA, Destination: destination, IdempotencyKey: "fixture:" + destination, Payload: []byte(`{}`),
		})
	}
	handler := orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
		return errors.New("fixture-provider-detail")
	})
	if count, err := outbox.Dispatch(ctx, handler); err != nil || count != len(destinations) {
		t.Fatalf("dispatch returned count=%d err=%v", count, err)
	}
	if bytes.Contains(logged.Bytes(), []byte("fixture-provider-detail")) ||
		bytes.Count(logged.Bytes(), []byte("level=DEBUG")) < len(destinations) {
		t.Fatal("secret delivery DEBUG did not retain only closed error classes")
	}
}
