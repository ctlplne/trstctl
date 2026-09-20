// SPDX-License-Identifier: BUSL-1.1

package backup

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestBackupHistoryRecordForProofPreservesOuterEnvelopeBytes(t *testing.T) {
	t.Parallel()
	before := []byte(`{"schedule_id":"schedule-1","run_id":"run-1","status":"failed","error":"provider-credential"}`)
	after := []byte(`{"schedule_id":"schedule-1","run_id":"run-1","status":"failed","error":"execution_failed"}`)
	beforeToken, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	afterToken, err := json.Marshal(after)
	if err != nil {
		t.Fatal(err)
	}
	stored := []byte("{ \"future\" : [1, 2], \"actor\" : null, \"data\" : " + string(beforeToken) +
		", \"time\" : \"2026-08-11T12:00:00Z\", \"tenant_id\" : \"11111111-1111-1111-1111-111111111111\", \"type\" : \"secret.rotation_schedule.ran\", \"id\" : \"legacy-run-1\" }")
	rec := record{
		Sequence: 1, Subject: "events.secret.rotation_schedule.ran", MessageID: "legacy-run-1",
		Stored: stored, ID: "legacy-run-1", Type: "secret.rotation_schedule.ran",
		TenantID: "11111111-1111-1111-1111-111111111111", SchemaVersion: 1,
		Time: time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC), Data: before,
	}
	history, err := backupHistoryRecordForProof(rec, after)
	if err != nil {
		t.Fatalf("backupHistoryRecordForProof: %v", err)
	}
	want := bytes.Replace(stored, beforeToken, afterToken, 1)
	if !bytes.Equal(history.Stored, want) {
		t.Fatalf("proof envelope changed unrelated bytes:\n got: %s\nwant: %s", history.Stored, want)
	}
}
