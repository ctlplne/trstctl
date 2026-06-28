package backup

import (
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

func postgresStateManifestOnlyStream(t *testing.T, tables []string) string {
	t.Helper()
	var b strings.Builder
	dig := newDigest(nil)
	enc := json.NewEncoder(io.MultiWriter(&b, dig))
	if err := enc.Encode(postgresStateHeader{
		Format: postgresStateFormatTag, Version: postgresStateVersion,
		CreatedAt: time.Unix(0, 0).UTC(), Tables: tables,
	}); err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(&b).Encode(postgresStateTrailer{
		Format: postgresStateTrailerTag, SHA256: dig.sumHex(),
		Records: 0, Tables: map[string]int{},
	}); err != nil {
		t.Fatal(err)
	}
	return b.String()
}
