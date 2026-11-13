// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A168-L3 Done-when (served): the managed-key inventory shows each key's
// provider dates as its lifecycle results recorded them — the provider's own
// creation date (not the moment trstctl's operation completed) and, once
// deletion is scheduled, the provider's deletion date — and a result that
// reports no dates never erases them.
func TestServedManagedKeyInventoryShowsTheProvidersOwnDatesA168L3(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ManagedKeyCustody = api.ManagedKeyCustodyConfiguration{Enabled: true, Provider: config.ManagedKeyProviderAWS}
		d.ManagedKeyFactory = func(ManagedKeyServiceDeps) (api.ManagedKeyService, error) { return fakeManagedKeyService{}, nil }
	})
	ctx := context.Background()
	token := seedServedAPIToken(t, ctx, h.store, h.tenant, "a168l3-reader", []string{string(authz.KeysRead)})
	created := time.Date(2026, 11, 13, 9, 0, 1, 0, time.UTC)
	deletion := created.Add(30 * 24 * time.Hour)
	const keyID = "a168l3-served-key"

	generate := projections.ManagedKeyCommand{OperationID: "a168l3-served-generate", Provider: "aws-kms", Action: "generate",
		Algorithm: "ECDSA-P256", RequestBinding: "a168l3-served-generate-binding"}
	for _, step := range []struct {
		eventType string
		payload   any
	}{
		{projections.EventManagedKeyCommandRequested, generate},
		{projections.EventManagedKeyCommandCompleted, projections.ManagedKeyCommandCompleted{ManagedKeyCommand: generate,
			ResultKeyID: keyID, PublicDER: []byte("public-key-metadata"), State: "active", ProviderCreatedAt: &created}},
	} {
		raw, err := json.Marshal(step.payload)
		if err != nil {
			t.Fatal(err)
		}
		event, err := h.log.Append(ctx, events.Event{Type: step.eventType, TenantID: h.tenant, Data: raw})
		if err != nil {
			t.Fatalf("append %s: %v", step.eventType, err)
		}
		if err := projections.New(h.store).Apply(ctx, event); err != nil {
			t.Fatalf("project %s: %v", step.eventType, err)
		}
	}
	type record struct {
		KeyID              string     `json:"key_id"`
		State              string     `json:"state"`
		CreatedAt          time.Time  `json:"created_at"`
		ProviderCreatedAt  *time.Time `json:"provider_created_at"`
		ProviderDeletionAt *time.Time `json:"provider_deletion_at"`
	}
	read := func() record {
		t.Helper()
		code, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/managed-keys/aws-kms/"+url.PathEscape(keyID), token, "", nil)
		var got record
		if code != http.StatusOK || json.Unmarshal(body, &got) != nil {
			t.Fatalf("GET managed key = %d %s", code, body)
		}
		code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/managed-keys?limit=100", token, "", nil)
		var list struct {
			Items []record `json:"items"`
		}
		if code != http.StatusOK || json.Unmarshal(body, &list) != nil || len(list.Items) != 1 || list.Items[0].KeyID != got.KeyID ||
			!sameRecordDates(list.Items[0].ProviderCreatedAt, got.ProviderCreatedAt) || !sameRecordDates(list.Items[0].ProviderDeletionAt, got.ProviderDeletionAt) {
			t.Fatalf("inventory = %d %s", code, body)
		}
		return got
	}
	got := read()
	if got.ProviderCreatedAt == nil || !got.ProviderCreatedAt.Equal(created) || got.ProviderDeletionAt != nil || got.CreatedAt.Equal(created) {
		t.Fatalf("generated key = %+v, want the provider's creation date %s apart from the record's own time", got, created)
	}

	// An approved zeroize completes as the projection applies it, reporting
	// the provider's scheduled deletion; a later result without dates keeps
	// both.
	apply := func(op store.ManagedKeyOperation) {
		t.Helper()
		payload, _ := json.Marshal(op)
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			if err := h.store.ApplyManagedKeyIntentTx(ctx, tx, op, payload); err != nil {
				return err
			}
			op.Status = "completed"
			return h.store.ApplyManagedKeyCompletedTx(ctx, tx, op)
		}); err != nil {
			t.Fatalf("apply %s: %v", op.Action, err)
		}
	}
	zeroize := store.ManagedKeyOperation{TenantID: h.tenant, OperationID: "a168l3-served-zeroize", Provider: "aws-kms",
		Action: "zeroize", KeyID: keyID, Algorithm: "ECDSA-P256", RequestBinding: "a168l3-served-zeroize-binding",
		ResultKeyID: keyID, ResultState: "deletion_pending", PublicDER: []byte("public-key-metadata"),
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), ProviderCreatedAt: &created, ProviderDeletionAt: &deletion}
	apply(zeroize)
	got = read()
	if got.State != "deletion_pending" || got.ProviderDeletionAt == nil || !got.ProviderDeletionAt.Equal(deletion) ||
		got.ProviderCreatedAt == nil || !got.ProviderCreatedAt.Equal(created) {
		t.Fatalf("zeroized key = %+v, want the provider's deletion date %s", got, deletion)
	}
	undated := zeroize
	undated.OperationID, undated.RequestBinding = "a168l3-served-zeroize-replay", "a168l3-served-zeroize-replay-binding"
	undated.ProviderCreatedAt, undated.ProviderDeletionAt = nil, nil
	apply(undated)
	if got = read(); got.ProviderCreatedAt == nil || got.ProviderDeletionAt == nil || !got.ProviderDeletionAt.Equal(deletion) {
		t.Fatalf("a result without dates erased them: %+v", got)
	}
}

func sameRecordDates(a, b *time.Time) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && a.Equal(*b))
}
