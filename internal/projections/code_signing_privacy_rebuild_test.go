// SPDX-License-Identifier: MPL-2.0

package projections_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestLegacyCodeSigningPrivacyMappingRebuildsWithoutServingRawKey(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	tenantID := uuid.NewString()
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantID, Name: "legacy-code-signing-privacy"}); err != nil {
		t.Fatal(err)
	}
	const rawKey = "release/alice@example.com/legacy"
	operationID := store.LegacyCodeSigningOperationID(tenantID, rawKey)
	mappedKey := store.LegacyCodeSigningStorageKey(operationID, rawKey)
	payload := projections.CodeSigningCommanded{
		OperationID: operationID, IdempotencyKey: mappedKey, Mode: "key",
		RequestHash: strings.Repeat("a", 64), SealedCommand: []byte("tenant-sealed-legacy-command"),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	event := events.Event{
		ID:   "codesign-event-77110000-0000-4000-8000-000000000001",
		Type: projections.EventCodeSigningCommanded, TenantID: tenantID,
		Time: time.Now().UTC(), SchemaVersion: 1, Data: data,
	}
	project := func() store.CodeSigningOperation {
		t.Helper()
		if err := projections.New(s).Apply(ctx, event); err != nil {
			t.Fatalf("project sanitized legacy command: %v", err)
		}
		op, found, err := s.CodeSigningOperationByIdempotency(ctx, tenantID, rawKey)
		if err != nil || !found {
			t.Fatalf("lookup by transient raw retry key = found %t err=%v", found, err)
		}
		if op.OperationID != operationID || op.IdempotencyKey != mappedKey ||
			strings.Contains(op.IdempotencyKey, "alice@example.com") || bytes.Contains(data, []byte(rawKey)) {
			t.Fatalf("sanitized legacy projection leaked or changed identity: %+v event=%s", op, data)
		}
		return op
	}
	first := project()
	if _, err := s.SystemPool().Exec(ctx,
		`TRUNCATE code_signing_operations, outbox RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	rebuilt := project()
	if rebuilt.OperationID != first.OperationID || rebuilt.IdempotencyKey != first.IdempotencyKey ||
		!bytes.Equal(rebuilt.SealedCommand, first.SealedCommand) {
		t.Fatalf("cold projection differs: first=%+v rebuilt=%+v", first, rebuilt)
	}
}
