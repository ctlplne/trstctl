// SPDX-License-Identifier: MPL-2.0

package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
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

func TestDecodePostgresJSONByteaRequiresExactHexFormAUD109(t *testing.T) {
	got, err := decodePostgresJSONBytea(json.RawMessage(`"\\x7b7d"`))
	if err != nil || !bytes.Equal(got, []byte(`{}`)) {
		t.Fatalf("decode PostgreSQL bytea = %q, %v; want {}", got, err)
	}
	for _, raw := range []json.RawMessage{
		json.RawMessage(`"e30="`),
		json.RawMessage(`"\\x"`),
		json.RawMessage(`"\\xnot-hex"`),
		json.RawMessage(`null`),
	} {
		if decoded, err := decodePostgresJSONBytea(raw); err == nil {
			t.Fatalf("invalid PostgreSQL bytea %s decoded as %x", raw, decoded)
		}
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

func TestPrivacyErasurePreparationPrecedesOperationInPostgresRestoreOrder(t *testing.T) {
	order, err := postgresStateRestoreOrder()
	if err != nil {
		t.Fatalf("postgresStateRestoreOrder: %v", err)
	}
	positions := make(map[string]int, len(order))
	for index, table := range order {
		positions[table] = index
	}
	preparation, havePreparation := positions["privacy_subject_erasure_preparations"]
	operation, haveOperation := positions["privacy_subject_erasure_operations"]
	if !havePreparation || !haveOperation {
		t.Fatalf("privacy recovery tables missing from restore order: %v", order)
	}
	if preparation >= operation {
		t.Fatalf("privacy recovery restore order = preparation:%d operation:%d; crash marker must restore first", preparation, operation)
	}
}

func TestApprovedTargetFenceIsInPostgresRestoreOrderAUD77(t *testing.T) {
	order, err := postgresStateRestoreOrder()
	if err != nil {
		t.Fatalf("postgresStateRestoreOrder: %v", err)
	}
	for _, table := range order {
		if table == "approved_target_event_fences" {
			return
		}
	}
	t.Fatalf("approved_target_event_fences missing from restore order: %v", order)
}

func TestSecretRotationCommandIsInIndependentPostgresRestoreOrderAUD106(t *testing.T) {
	order, err := postgresStateRestoreOrder()
	if err != nil {
		t.Fatalf("postgresStateRestoreOrder: %v", err)
	}
	positions := make(map[string]int, len(order))
	for index, table := range order {
		positions[table] = index
	}
	command, ok := positions["secret_rotation_schedule_commands"]
	if !ok {
		t.Fatalf("secret_rotation_schedule_commands missing from restore order: %v", order)
	}
	if _, projected := positions["secret_rotation_schedules"]; projected {
		t.Fatal("rebuildable secret_rotation_schedules must not enter independent PostgreSQL restore order")
	}
	cursor, ok := positions["secret_rotation_schedule_scan_cursors"]
	if !ok {
		t.Fatalf("secret_rotation_schedule_scan_cursors missing from restore order: %v", order)
	}
	tick, ok := positions["secret_rotation_schedule_ticks"]
	if !ok {
		t.Fatalf("secret_rotation_schedule_ticks missing from restore order: %v", order)
	}
	tickRow, ok := positions["secret_rotation_schedule_tick_rows"]
	if !ok {
		t.Fatalf("secret_rotation_schedule_tick_rows missing from restore order: %v", order)
	}
	if cursor <= positions["idempotency_keys"] || cursor >= tick {
		t.Fatalf("schedule cursor restore position=%d, want it after outer keys and before tick receivers: %v", cursor, order)
	}
	if tick <= positions["idempotency_keys"] || tick <= cursor || tick >= tickRow {
		t.Fatalf("schedule tick restore position=%d, want it after idempotency/cursor authority and before child commands: %v", tick, order)
	}
	if tickRow <= tick || tickRow >= command {
		t.Fatalf("schedule tick row restore position=%d, want it after parent ticks and before commands: %v", tickRow, order)
	}
	if command <= tickRow || command >= positions["secret_store"] {
		t.Fatalf("schedule command restore position=%d, want it after immutable tick rows in the independent receiver group: %v", command, order)
	}
}

func TestApplicationSecretFenceActorPostgresStateRoundTripAUD77(t *testing.T) {
	const (
		subject = "backup-secret-actor"
		ref     = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	)
	backupRow := json.RawMessage(`{
		"tenant_id":"11111111-1111-1111-1111-111111111111",
		"secret_name":"backup/pending",
		"actor":{"subject":"backup-secret-actor","roles":["auditor","operator"]},
		"actor_subject_ref":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	}`)
	normalized, err := normalizePostgresStateRows(
		"application_secret_mutation_fences", []json.RawMessage{backupRow})
	if err != nil {
		t.Fatalf("normalize application-secret fence backup row: %v", err)
	}
	if len(normalized) != 1 {
		t.Fatalf("normalized fence rows=%d, want 1", len(normalized))
	}
	var restored struct {
		Actor struct {
			Subject string   `json:"subject"`
			Roles   []string `json:"roles"`
		} `json:"actor"`
		ActorSubjectRef string `json:"actor_subject_ref"`
	}
	if err := json.Unmarshal(normalized[0], &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Actor.Subject != subject ||
		!reflect.DeepEqual(restored.Actor.Roles, []string{"auditor", "operator"}) ||
		restored.ActorSubjectRef != ref {
		t.Fatalf("application-secret actor changed across PostgreSQL-state row round trip: %+v", restored)
	}
	found := false
	for _, table := range postgresStateTables() {
		found = found || table == "application_secret_mutation_fences"
	}
	if !found {
		t.Fatal("application_secret_mutation_fences is absent from PostgreSQL-state backup manifest")
	}
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

func TestNormalizeLegacyOutboxRowsAddsOnlyNeutralNonSecretAuthorityAUD109(t *testing.T) {
	legacy := []json.RawMessage{
		json.RawMessage(`{"id":1,"tenant_id":"11111111-1111-1111-1111-111111111111","destination":"webhook.audit","attempts":3}`),
		json.RawMessage(`{"id":2,"tenant_id":"11111111-1111-1111-1111-111111111111","destination":"secret.sync.ci","attempts":2}`),
	}
	normalized, err := normalizePostgresStateRows("outbox", legacy)
	if err != nil {
		t.Fatal(err)
	}
	var neutral map[string]json.RawMessage
	if err := json.Unmarshal(normalized[0], &neutral); err != nil {
		t.Fatal(err)
	}
	for field, want := range map[string]string{
		"secret_sync_target_order":          "null",
		"secret_sync_order_from_event":      "null",
		"secret_sync_receiver_effect_state": `"none"`,
		"secret_sync_receiver_io_starts":    "0",
		"secret_sync_failure_detail":        `""`,
		"secret_sync_failure_attempts":      "0",
	} {
		if got := string(neutral[field]); got != want {
			t.Fatalf("neutral legacy outbox %s=%s, want %s", field, got, want)
		}
	}
	if !bytes.Equal(normalized[1], legacy[1]) {
		t.Fatalf("secret-sync legacy row was guessed before rebuilt-job reconciliation: got=%s want=%s", normalized[1], legacy[1])
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
