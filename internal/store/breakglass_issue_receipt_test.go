// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"encoding/json"
	"math"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

func TestBreakglassIssueReceiptRejectsSequencesOutsidePostgresBigint(t *testing.T) {
	var nilStore *store.Store
	receipt := store.BreakglassIssueReceipt{
		TenantID: "11111111-1111-4111-8111-111111111111", CeremonyID: "22222222-2222-4222-8222-222222222222",
		RequestID: "incident-1", Subject: "recovery.test", RequestDigest: "digest-1",
		Bundle: json.RawMessage(`{"cert_der":"AQ=="}`), EventSequence: uint64(math.MaxInt64) + 1, IssuedAt: time.Now(),
	}
	if err := nilStore.ApplyBreakglassIssueReceiptTx(context.Background(), nil, receipt); err == nil {
		t.Fatal("signed receipt sequence overflow reached SQL")
	}
	if _, err := nilStore.ListBreakglassIssueReceipts(context.Background(), receipt.TenantID, receipt.EventSequence, 20); err == nil {
		t.Fatal("pagination cursor sequence overflow reached SQL")
	}
	if err := nilStore.MarkBreakglassIssueCheckedThrough(context.Background(), receipt.EventSequence); err == nil {
		t.Fatal("recovery cursor sequence overflow reached SQL")
	}
}
