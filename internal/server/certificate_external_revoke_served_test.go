// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/vaultpki"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestServedExactExternalCertificateRevocationWaitsForItsCA(t *testing.T) {
	failed, calls := true, 0
	var selected store.Certificate
	upstream := revocationTestCA{revoke: func(_ context.Context, request ca.RevokeRequest) error {
		calls++
		if request.Serial != selected.Serial || request.ReasonCode != 4 {
			t.Fatal("revocation reached the wrong serial or reason")
		}
		if failed {
			return errors.New("controlled issuer outage")
		}
		return nil
	}}
	h, token, _ := servedPublicBrokerRevocationFixture(t, func(d *Deps) {
		d.ExternalCAs = []ExternalCA{{ID: "retained-vault", Type: "vaultpki", Name: "Retained Vault", CA: upstream}}
	})
	dispatcher := h.srv.obHandler.(*issuanceDispatcher)
	i := &issuanceDispatcherHarness{store: h.store, log: h.log, orch: h.srv.orch, outbox: h.srv.outbox, handler: dispatcher, tenant: h.tenant}
	owner, err := h.srv.orch.CreateOwner(t.Context(), h.tenant, "service", "Exact external revocation", "")
	if err != nil {
		t.Fatal(err)
	}
	selected = recordRevocationTestLeaf(t, i, owner.ID, "external.example.test", "retained-vault", "selected", "")
	unrelated := recordRevocationTestLeaf(t, i, owner.ID, "external.example.test", "retained-vault", "unrelated", "")
	const route = "/api/v1/certificates/bulk-revoke"
	request := map[string]any{"certificate_ids": []string{selected.ID}, "reason": "superseded"}
	status, raw := secretsReqKey(t, h, http.MethodPost, route, token, "exact-vault-command", request)
	if status != http.StatusOK || !bytes.Contains(raw, []byte(`"total_queued":1`)) || !bytes.Contains(raw, []byte(`"total_revoked":0`)) || calls != 0 {
		t.Fatalf("external revocation must queue without a provider call or false success: HTTP %d %s calls=%d", status, raw, calls)
	}
	row := pendingOutboxByDestination(t, i, "revocation.publish")
	message := orchestrator.Message{ID: row.ID, TenantID: h.tenant, Destination: row.Destination, Payload: row.Payload, IdempotencyKey: row.IdempotencyKey}
	var command store.ExternalCertificateRevocation
	if err := json.Unmarshal(message.Payload, &command); err != nil {
		t.Fatal(err)
	}
	retained, found, err := h.log.EventByID(t.Context(), command.EventID)
	if err != nil || !found || retained.SchemaVersion != projections.CertificateExternalRevocationSchemaVersion {
		t.Fatal("external command did not retain its new event version")
	}
	legacy := retained
	legacy.ID, legacy.SchemaVersion = "legacy-cannot-queue-external", 1
	if err := h.srv.proj.Apply(t.Context(), legacy); err == nil {
		t.Fatal("legacy event version acquired a remote effect")
	}
	foreign := message
	foreign.TenantID = "22222222-2222-4222-8222-222222222222"
	if err := dispatcher.Deliver(t.Context(), foreign); err == nil || calls != 0 {
		t.Fatal("another tenant reused the retained authority")
	}
	if err := dispatcher.Deliver(t.Context(), message); err == nil {
		t.Fatal("issuer outage reported success")
	}
	current, err := h.store.GetCertificate(t.Context(), h.tenant, selected.ID)
	if err != nil || current.Status != "active" {
		t.Fatal("queued/failed request falsely marked certificate revoked")
	}
	failed = false
	if err := dispatcher.Deliver(t.Context(), message); err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.Deliver(t.Context(), message); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("replay repeated issuer action: calls=%d", calls)
	}
	current, err = h.store.GetCertificate(t.Context(), h.tenant, selected.ID)
	if err != nil || current.Status != "revoked" || current.RevocationReason != "superseded" {
		t.Fatal("accepted issuer result was not projected")
	}
	other, err := h.store.GetCertificate(t.Context(), h.tenant, unrelated.ID)
	if err != nil || other.Status != "active" {
		t.Fatal("revoked a different same-name certificate")
	}
	if _, found, err := h.store.LookupIssuedCert(t.Context(), h.tenant, IssuingCAID(), selected.Serial); err != nil || found {
		t.Fatal("external serial entered platform ledger")
	}
	status, replay := secretsReqKey(t, h, http.MethodPost, route, token, "exact-vault-command", request)
	if status != http.StatusOK || !bytes.Equal(raw, replay) {
		t.Fatal("unchanged retry lost the original accepted result")
	}
	// A rebuilt worker must use the immutable result after its finite cache
	// disappears. Reapplying the command cannot enqueue a second logical effect.
	resultID := "certificate.external-revoked:" + crypto.SHA256Hex([]byte(h.tenant+"\x00"+command.EventID+"\x00"+command.CertificateID))
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `DELETE FROM idempotency_keys WHERE tenant_id=$1 AND key=$2`, h.tenant, "revoke-exact:"+resultID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.log.Replay(t.Context(), 0, func(event events.Event) error {
		if event.Type == projections.EventCertificateRevocationBatchApplied {
			return h.srv.proj.Apply(t.Context(), event)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.Deliver(t.Context(), message); err != nil || calls != 2 {
		t.Fatalf("cache loss repeated the accepted CA action: %v, calls=%d", err, calls)
	}
	var commandCount int
	if err := h.store.SystemPool().QueryRow(t.Context(), `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2`, h.tenant, row.IdempotencyKey).Scan(&commandCount); err != nil || commandCount != 1 {
		t.Fatal("replay duplicated the exact external command")
	}
	var tampered map[string]any
	if err := json.Unmarshal(message.Payload, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered["certificate_id"] = unrelated.ID
	message.Payload, _ = json.Marshal(tampered)
	if err := dispatcher.Deliver(t.Context(), message); err == nil || calls != 2 {
		t.Fatal("worker accepted a changed exact command")
	}
}

func TestServedExactVaultRevocationRefusalDoesNotBecomeRevoked(t *testing.T) {
	var confirmed atomic.Bool
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if confirmed.Load() {
			_, _ = w.Write([]byte(`{"data":{"revocation_time":1433269787}}`))
		} else {
			// Exact semantic shape observed from stock Vault for an expired leaf.
			_, _ = w.Write([]byte(`{"data":null,"warnings":["certificate already expired; refusing to add to CRL"]}`))
		}
	}))
	defer provider.Close()
	upstream := vaultpki.New(vaultpki.Config{Name: "vault-confirmation", BaseURL: provider.URL, Token: []byte("local-qa-token"), Role: "web"}, vaultpki.WithHTTPClient(provider.Client()))
	defer upstream.Destroy()
	h, token, _ := servedPublicBrokerRevocationFixture(t, func(d *Deps) {
		d.ExternalCAs = []ExternalCA{{ID: "retained-vault", Type: "vaultpki", Name: "Retained Vault", CA: upstream}}
	})
	dispatcher := h.srv.obHandler.(*issuanceDispatcher)
	harness := &issuanceDispatcherHarness{store: h.store, log: h.log, orch: h.srv.orch, outbox: h.srv.outbox, handler: dispatcher, tenant: h.tenant}
	owner, err := h.srv.orch.CreateOwner(t.Context(), h.tenant, "service", "Vault confirmation", "")
	if err != nil {
		t.Fatal(err)
	}
	selected := recordRevocationTestLeaf(t, harness, owner.ID, "external.example.test", "retained-vault", "selected", "")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", token, "vault-confirmation-command", map[string]any{"certificate_ids": []string{selected.ID}, "reason": "superseded"})
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"total_queued":1`)) {
		t.Fatalf("queue: HTTP %d %s", status, body)
	}
	row := pendingOutboxByDestination(t, harness, "revocation.publish")
	message := orchestrator.Message{ID: row.ID, TenantID: h.tenant, Destination: row.Destination, Payload: row.Payload, IdempotencyKey: row.IdempotencyKey}
	if err := dispatcher.Deliver(t.Context(), message); err == nil {
		t.Fatal("Vault warning became a successful revocation")
	}
	current, err := h.store.GetCertificate(t.Context(), h.tenant, selected.ID)
	if err != nil || current.Status != "active" {
		t.Fatalf("unconfirmed certificate changed state: %s %v", current.Status, err)
	}
	var command store.ExternalCertificateRevocation
	if err := json.Unmarshal(row.Payload, &command); err != nil {
		t.Fatal(err)
	}
	resultID := "certificate.external-revoked:" + crypto.SHA256Hex([]byte(h.tenant+"\x00"+command.EventID+"\x00"+selected.ID))
	if _, found, err := h.log.EventByID(t.Context(), resultID); err != nil || found {
		t.Fatalf("unconfirmed issuer created a completion event: %t %v", found, err)
	}
	// A later confirmed issuer response completes the original durable command.
	confirmed.Store(true)
	if err := dispatcher.Deliver(t.Context(), message); err != nil {
		t.Fatal(err)
	}
	current, err = h.store.GetCertificate(t.Context(), h.tenant, selected.ID)
	if err != nil || current.Status != "revoked" || calls.Load() != 2 {
		t.Fatalf("confirmed result: %s calls=%d err=%v", current.Status, calls.Load(), err)
	}
}
