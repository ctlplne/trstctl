// SPDX-License-Identifier: MPL-2.0

package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

func TestPostgresStateRestoreOrderReturnsErrors(t *testing.T) {
	order, err := postgresStateRestoreOrder()
	if err != nil {
		t.Fatalf("postgresStateRestoreOrder: %v", err)
	}
	if len(order) != len(postgresStateTables()) {
		t.Fatalf("restore order has %d tables, manifest has %d", len(order), len(postgresStateTables()))
	}

	unsafe := append([]string(nil), order...)
	unsafe[0] = "outbox;drop"
	if err := validatePostgresStateRestoreOrder(unsafe); err == nil || !strings.Contains(err.Error(), "unsafe table name") {
		t.Fatalf("unsafe restore order error = %v, want unsafe table name", err)
	}

	missing := append([]string(nil), order[:len(order)-1]...)
	if err := validatePostgresStateRestoreOrder(missing); err == nil || !strings.Contains(err.Error(), "table manifest") {
		t.Fatalf("short restore order error = %v, want table manifest mismatch", err)
	}
}

func TestDeploymentTargetRestoreOrderIsDeterministic(t *testing.T) {
	first, err := postgresStateRestoreOrder()
	if err != nil {
		t.Fatalf("first postgresStateRestoreOrder: %v", err)
	}
	second, err := postgresStateRestoreOrder()
	if err != nil {
		t.Fatalf("second postgresStateRestoreOrder: %v", err)
	}
	if strings.Join(first, ",") != strings.Join(second, ",") {
		t.Fatalf("restore order changed between calls: first=%v second=%v", first, second)
	}

	position := make(map[string]int, len(first))
	for i, table := range first {
		position[table] = i
	}
	revision, haveRevision := position["deployment_target_revisions"]
	target, haveTarget := position["deployment_targets"]
	if !haveRevision || !haveTarget {
		t.Fatalf("restore order must contain both target tables: %v", first)
	}
	if revision >= target {
		t.Fatalf("deployment target restore order = revisions:%d targets:%d; revisions must restore first", revision, target)
	}
}

func TestPrivacyErasureOperationIsInPostgresRestoreOrder(t *testing.T) {
	order, err := postgresStateRestoreOrder()
	if err != nil {
		t.Fatalf("postgresStateRestoreOrder: %v", err)
	}
	for _, table := range order {
		if table == "privacy_subject_erasure_operations" {
			return
		}
	}
	t.Fatalf("privacy_subject_erasure_operations missing from restore order: %v", order)
}

func TestRestorePostgresStateRejectsBadManifestBeforeStoreUse(t *testing.T) {
	tables := postgresStateTables()
	if len(tables) == 0 {
		t.Fatal("test setup: postgres state manifest is empty")
	}
	stream := postgresStateManifestOnlyStream(t, tables[:len(tables)-1])

	summary, err := RestorePostgresState(context.Background(), nil, strings.NewReader(stream))
	if err == nil {
		t.Fatal("RestorePostgresState must reject a bad table manifest")
	}
	if !strings.Contains(err.Error(), "table manifest") {
		t.Fatalf("RestorePostgresState error = %v, want table manifest error", err)
	}
	if summary.Records != 0 || len(summary.Tables) != 0 {
		t.Fatalf("summary = %+v, want zero summary before store use", summary)
	}
}

func TestVerifyPostgresStateExposesPairedEventCutWithoutStore(t *testing.T) {
	const cut = uint64(37)
	stream := postgresStateManifestOnlyStreamAtCut(t, postgresStateTables(), cut)

	summary, err := VerifyPostgresState(strings.NewReader(stream))
	if err != nil {
		t.Fatalf("VerifyPostgresState: %v", err)
	}
	if summary.EventCutSequence != cut {
		t.Fatalf("verified event cut = %d, want %d", summary.EventCutSequence, cut)
	}
	if summary.Records != 0 || len(summary.Tables) != 0 {
		t.Fatalf("verified summary = %+v, want empty artifact at cut %d", summary, cut)
	}
}

func TestNormalizeLegacyPostgresStateRowsAddsRawIdempotencyCodec(t *testing.T) {
	legacy := []json.RawMessage{
		json.RawMessage(`{"tenant_id":"11111111-1111-1111-1111-111111111111","key":"legacy","status":"completed","result":"\\x736563726574"}`),
		json.RawMessage(`{"tenant_id":"22222222-2222-2222-2222-222222222222","key":"already-sealed","status":"completed","result":"\\x43534c31","result_codec":"sealed-row-v1"}`),
	}
	normalized, err := normalizePostgresStateRows("idempotency_keys", legacy)
	if err != nil {
		t.Fatalf("normalize legacy idempotency rows: %v", err)
	}
	if len(normalized) != len(legacy) {
		t.Fatalf("normalized rows=%d, want %d", len(normalized), len(legacy))
	}
	for index, wantCodec := range []string{"raw-v0", "sealed-row-v1"} {
		var row map[string]json.RawMessage
		if err := json.Unmarshal(normalized[index], &row); err != nil {
			t.Fatalf("decode normalized row %d: %v", index, err)
		}
		var gotCodec string
		if err := json.Unmarshal(row["result_codec"], &gotCodec); err != nil {
			t.Fatalf("decode normalized codec %d: %v", index, err)
		}
		if gotCodec != wantCodec {
			t.Fatalf("row %d result_codec=%q, want %q", index, gotCodec, wantCodec)
		}
	}

	other := []json.RawMessage{json.RawMessage(`{"tenant_id":"11111111-1111-1111-1111-111111111111","name":"untouched"}`)}
	untouched, err := normalizePostgresStateRows("secret_store", other)
	if err != nil {
		t.Fatalf("normalize unrelated rows: %v", err)
	}
	if len(untouched) != 1 || !bytes.Equal(untouched[0], other[0]) {
		t.Fatalf("unrelated backup row changed: got=%s want=%s", untouched[0], other[0])
	}
}

func TestNormalizeLegacyPostgresStateRowsRejectsNullObject(t *testing.T) {
	if _, err := normalizePostgresStateRows("idempotency_keys", []json.RawMessage{json.RawMessage(`null`)}); err == nil {
		t.Fatal("normalize accepted a null idempotency row; want a typed error instead of a nil-map panic")
	}
}

func postgresStateManifestOnlyStream(t *testing.T, tables []string) string {
	return postgresStateManifestOnlyStreamAtCut(t, tables, 0)
}

func postgresStateManifestOnlyStreamAtCut(t *testing.T, tables []string, cut uint64) string {
	t.Helper()
	var b strings.Builder
	dig := newDigest(nil)
	enc := json.NewEncoder(io.MultiWriter(&b, dig))
	if err := enc.Encode(postgresStateHeader{
		Format: postgresStateFormatTag, Version: postgresStateVersion,
		CreatedAt: time.Unix(0, 0).UTC(), Tables: tables, EventCutSequence: cut,
	}); err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(&b).Encode(postgresStateTrailer{
		Format: postgresStateTrailerTag, SHA256: dig.sumHex(),
		Records: 0, Tables: map[string]int{}, EventCutSequence: cut,
	}); err != nil {
		t.Fatal(err)
	}
	return b.String()
}
