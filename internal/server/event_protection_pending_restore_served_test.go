// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
)

func TestNormalRecoveryCallbackRefusesActualPendingBackupBinding(t *testing.T) {
	source, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = source.Close() })
	for _, id := range []string{"pending-first", "pending-second"} {
		if _, err := source.Append(t.Context(), events.Event{ID: id, Type: "fixture.public", TenantID: "7ddf21eb-e38a-4ac1-8b78-425665660736", Data: []byte(`{"fixture":true}`)}); err != nil {
			t.Fatal(err)
		}
	}
	var history []events.BackupHistoryRecord
	var raw bytes.Buffer
	if err := source.ExportBackupHistoryThrough(t.Context(), 2, func(record events.BackupHistoryRecord) error {
		record.Stored = bytes.Clone(record.Stored)
		history = append(history, record)
		raw.Write(record.Stored)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	st := newServerTestStore(t)
	key := testAuditSigningKey(t)
	cfg := config.Default().NATS
	cfg.Mode = config.NATSExternal
	cfg.URL = startBackupTestNATS(t).ClientURL()
	cfg.Replicas = 1
	cfg.AllowSingleReplica = true
	// Public deterministic fixture bytes, not a deployment credential.
	authorizer, err := crypto.NewBackupRestoreAuthorizer(bytes.Repeat([]byte{0x3a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authorizer.Destroy)
	target, err := openHistoryAwareEventLog(t.Context(), cfg, st, key, events.WithBackupRestoreAuthorizer(authorizer))
	if err != nil {
		t.Fatal(err)
	}
	interruption := errors.New("fixture exact restore interrupted")
	_, err = target.RestoreBackupHistory(t.Context(), 2, crypto.SHA256Hex(raw.Bytes()), func(yield func(events.BackupHistoryRecord) error) error {
		if err := yield(history[0]); err != nil {
			return err
		}
		return interruption
	})
	if !errors.Is(err, interruption) {
		t.Fatalf("partial restore did not reach original binding: %v", err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	called := false
	again, err := openSanitizedHistoryAwareEventLogWithRecovery(t.Context(), cfg, st, key, true, func(context.Context, *events.Log) error { called = true; return nil }, events.WithBackupRestoreAuthorizer(authorizer))
	if again != nil {
		_ = again.Close()
	}
	if !errors.Is(err, events.ErrBackupRestoreIncomplete) || called {
		t.Fatalf("recovery crossed incomplete exact backup binding: callback=%v err=%v", called, err)
	}
}
