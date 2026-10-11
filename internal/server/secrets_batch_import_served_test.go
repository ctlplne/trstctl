// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	cryptoseal "trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestServedSecretBatchImportIsAtomicAndIdempotent(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "secret batch import tenant")
	token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	path := "/api/v1/secrets/store/import"
	request := map[string]any{"prefix": "bulk/first", "values": map[string]string{
		"a": "batch-first", "b": "batch-second",
	}}
	status, first := secretsReqKey(t, h, http.MethodPost, path, token, "batch-first-key", request)
	if status != http.StatusCreated {
		t.Fatalf("first import status=%d body=%s", status, first)
	}
	status, replay := secretsReqKey(t, h, http.MethodPost, path, token, "batch-first-key", request)
	if status != http.StatusCreated || !bytes.Equal(first, replay) {
		t.Fatalf("exact import retry status=%d first=%s replay=%s", status, first, replay)
	}
	for name, want := range map[string]string{
		"a": "batch-first", "b": "batch-second",
	} {
		status, raw := secretsReq(t, h, http.MethodGet,
			"/api/v1/secrets/store/bulk/first/"+name, token, nil)
		var read struct {
			Value   string `json:"value"`
			Version int    `json:"version"`
		}
		if err := json.Unmarshal(raw, &read); err != nil || status != http.StatusOK ||
			read.Value != want || read.Version != 1 {
			t.Fatalf("independent readback %s status=%d version=%d err=%v", name, status, read.Version, err)
		}
	}
	changed := map[string]any{"prefix": "bulk/first", "values": map[string]string{
		"a": "changed", "b": "batch-second",
	}}
	status, _ = secretsReqKey(t, h, http.MethodPost, path, token, "batch-first-key", changed)
	if status != http.StatusConflict {
		t.Fatalf("changed body reused successful key: %d", status)
	}
	status, _ = secretsReqKey(t, h, http.MethodPost, path, token, "batch-collision-key",
		map[string]any{"prefix": "bulk/first", "values": map[string]string{
			"0-new": "must-not-commit", "a": "must-not-overwrite",
		}})
	if status != http.StatusConflict {
		t.Fatalf("collision import status=%d, want 409", status)
	}
	status, _ = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/store/bulk/first/0-new", token, nil)
	if status != http.StatusNotFound {
		t.Fatalf("collision partially imported an earlier sorted name: %d", status)
	}
	count := 0
	if err := h.log.Replay(context.Background(), 0, func(event events.Event) error {
		if event.Type == projections.EventApplicationSecretBatchImported {
			count++
			var payload projections.ApplicationSecretBatchImport
			if err := json.Unmarshal(event.Data, &payload); err != nil {
				return err
			}
			if len(payload.Items) != 2 || bytes.Contains(event.Data, []byte("batch-first")) ||
				bytes.Contains(event.Data, []byte("batch-second")) {
				t.Fatalf("batch source event leaked plaintext or lost items")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("batch source event count=%d, want one", count)
	}
}

func TestServedSecretBatchImportReconcilesBothCrashGaps(t *testing.T) {
	for _, afterAppend := range []bool{false, true} {
		label := "before-append"
		if afterAppend {
			label = "after-append"
		}
		t.Run(label, func(t *testing.T) {
			ctx := context.Background()
			h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
			registerServedTenant(t, h, "secret batch crash recovery "+label)
			token := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
			epoch, err := h.store.ApplicationSecretTenantEpoch(ctx, h.tenant)
			if err != nil {
				t.Fatal(err)
			}
			names := []string{"crash-" + label + "/a", "crash-" + label + "/b"}
			payload := projections.ApplicationSecretBatchImport{
				TenantEpoch: epoch, IdempotencyKeyDigest: strings.Repeat("a", 64),
				RequestBinding: strings.Repeat("b", 64), CommandEvidence: strings.Repeat("c", 64),
				Surface: "native",
			}
			for _, name := range names {
				sealed, sealErr := cryptoseal.Seal(h.kek, []byte("recovered-"+name),
					[]byte(h.tenant+"/secret-store/"+name))
				if sealErr != nil {
					t.Fatal(sealErr)
				}
				payload.Items = append(payload.Items,
					projections.ApplicationSecretBatchImportItem{Name: name, Sealed: sealed})
			}
			raw, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			id := "7bd2f615-651c-51f4-9c37-31a562b0e620"
			if afterAppend {
				id = "7bd2f615-651c-51f4-9c37-31a562b0e621"
			}
			batch, err := h.store.ClaimApplicationSecretImportBatch(ctx, store.ApplicationSecretImportBatch{
				TenantID: h.tenant, EventID: id, TenantEpoch: epoch,
				RequestBinding: payload.RequestBinding, Payload: raw,
				Actor:     &events.Actor{Subject: "crash-recovery-operator"},
				EventTime: time.Date(2026, 10, 10, 23, 30, 0, 0, time.UTC), Names: names,
			})
			if err != nil {
				t.Fatal(err)
			}
			if afterAppend {
				// A previously published event may retain nanoseconds even though
				// PostgreSQL rounded the durable command to microseconds.
				if _, err := h.log.Append(ctx, events.Event{
					ID: id, Type: projections.EventApplicationSecretBatchImported,
					TenantID: h.tenant, Time: batch.EventTime.Add(321 * time.Nanosecond),
					SchemaVersion: projections.ApplicationSecretBatchImportSchemaVersion,
					Data:          batch.Payload, Actor: batch.Actor,
				}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := h.store.GetApplicationSecretImportReceipt(ctx, h.tenant, id); !store.IsNotFound(err) {
				t.Fatalf("crash fixture already materialized a receipt: %v", err)
			}
			count, err := h.srv.api.ReconcileApplicationSecretMutationFences(ctx)
			if err != nil || count != 1 {
				t.Fatalf("reconcile pending batch count=%d err=%v", count, err)
			}
			if count, err := h.srv.api.ReconcileApplicationSecretMutationFences(ctx); err != nil || count != 0 {
				t.Fatalf("second reconcile repeated materialized batch count=%d err=%v", count, err)
			}
			receipt, err := h.store.GetApplicationSecretImportReceipt(ctx, h.tenant, id)
			if err != nil || len(receipt.Items) != len(names) {
				t.Fatalf("recovered receipt items=%d err=%v", len(receipt.Items), err)
			}
			for _, name := range names {
				status, body := secretsReq(t, h, http.MethodGet,
					"/api/v1/secrets/store/"+name, token, nil)
				var read struct {
					Value string `json:"value"`
				}
				if err := json.Unmarshal(body, &read); err != nil || status != http.StatusOK ||
					read.Value != "recovered-"+name {
					t.Fatalf("recovered readback name=%s status=%d err=%v", name, status, err)
				}
			}
		})
	}
}
