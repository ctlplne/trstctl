// SPDX-License-Identifier: MPL-2.0

package backup_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/backup"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestBackupRefusesPendingExactRestoreBeforeWritingHeader(t *testing.T) {
	ctx := context.Background()
	log, err := events.Open(ctx, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	when := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	data := []byte(`{"name":"partial"}`)
	stored, err := json.Marshal(struct {
		ID       string    `json:"id"`
		Type     string    `json:"type"`
		TenantID string    `json:"tenant_id"`
		Time     time.Time `json:"time"`
		Data     []byte    `json:"data"`
	}{
		ID: "partial-event", Type: "owner.updated",
		TenantID: "11111111-1111-1111-1111-111111111111", Time: when, Data: data,
	})
	if err != nil {
		t.Fatal(err)
	}
	record := events.BackupHistoryRecord{
		Sequence: 1, Subject: "events.owner.updated", MessageID: "partial-event", Stored: stored,
	}
	errCrash := errors.New("simulated process stop")
	_, err = log.RestoreBackupHistory(ctx, 2, strings.Repeat("a", 64), func(yield func(events.BackupHistoryRecord) error) error {
		if err := yield(record); err != nil {
			return err
		}
		return errCrash
	})
	if !errors.Is(err, errCrash) {
		t.Fatalf("partial restore = %v, want simulated stop", err)
	}

	var output bytes.Buffer
	if _, err := backup.WriteLogWithKeyThrough(ctx, log, &output, []byte("0123456789abcdef"), 2); !errors.Is(err, events.ErrBackupRestoreIncomplete) {
		t.Fatalf("pending restore backup = %v, want incomplete restore", err)
	}
	if output.Len() != 0 {
		t.Fatalf("pending restore backup wrote %d bytes before rejection", output.Len())
	}
}
