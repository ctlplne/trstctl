// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"testing"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Owner decision (batch 14): a key is recorded as compromised when its
// identity is revoked with reason keyCompromise, not only when the revocation
// publishes. Before, the record was written when revocation.publish delivered,
// so between the compromise report and that delivery the same key could be
// certified again in the tenant.
func TestServedKeyCompromiseRevocationRefusesTheKeyBeforeItPublishes(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	tok := seedScopedToken(t, h.store, h.tenant,
		"owners:read", "owners:write", "identities:read", "identities:write", "certs:read", "certs:issue")
	owner, err := h.store.CreateOwner(ctx, store.Owner{TenantID: h.tenant, Kind: store.OwnerWorkload, Name: "compromise-window"})
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csrFor := func(name string) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: badSubjectCSR(t, key,
			crypto.CertificateRequestTemplate{CommonName: name, DNSNames: []string{name}})}))
	}
	identityNamed := func(name string) string {
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{
			"owner_id": owner.ID, "kind": "x509", "name": name,
		})
		var ident struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &ident) != nil {
			t.Fatalf("create identity %s = %d: %s", name, status, body)
		}
		return ident.ID
	}

	victim := identityNamed("victim.example.test")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+victim+"/transitions", tok,
		"victim-issue", map[string]any{"to": "issued", "reason": "first key", "subject_csr_pem": csrFor("victim.example.test")})
	if status != http.StatusOK {
		t.Fatalf("issue the victim = %d: %s", status, body)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain issuance: %v", err)
	}
	leaves, err := h.store.IdentityRevocationCertificates(ctx, h.tenant, victim, 101)
	if err != nil || len(leaves) != 1 {
		t.Fatalf("victim leaves = %d, %v; want the one issued", len(leaves), err)
	}
	leaf := leaves[0]

	status, revoked := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+victim+"/transitions", tok,
		"victim-compromised", map[string]any{"to": "revoked", "reason": "keyCompromise"})
	if status != http.StatusOK {
		t.Fatalf("revoke the victim for keyCompromise = %d: %s", status, revoked)
	}
	// The publication has not run: the certificate itself is still active.
	if current, err := h.store.GetCertificate(ctx, h.tenant, leaf.ID); err != nil || current.Status != "active" {
		t.Fatalf("the revocation published before the outbox ran: %+v %v", current.Status, err)
	}

	// The same key is refused for another identity now, naming why, and
	// nothing is recorded for the refused request.
	other := identityNamed("other.example.test")
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+other+"/transitions", tok,
		"other-issue", map[string]any{"to": "issued", "reason": "same key", "subject_csr_pem": csrFor("other.example.test")})
	if status != http.StatusBadRequest || !bytes.Contains(body, []byte("recorded as compromised")) {
		t.Fatalf("issuance for the compromised key before the publish = %d, want 400 naming the record: %s", status, body)
	}
	if got, err := h.store.GetIdentity(ctx, h.tenant, other); err != nil || got.Status != "requested" {
		t.Fatalf("refused transition moved the identity: %s %v", got.Status, err)
	}
	if n := eventCount(t, h.log, h.tenant, projections.EventCertificateSubjectKeyCompromised); n != 1 {
		t.Fatalf("compromised subject key events = %d, want one for the one certificate", n)
	}

	// A retried command records nothing twice, and the publish converges on
	// the same record.
	status, retry := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+victim+"/transitions", tok,
		"victim-compromised", map[string]any{"to": "revoked", "reason": "keyCompromise"})
	if status != http.StatusOK || !bytes.Equal(retry, revoked) {
		t.Fatalf("retried revocation = %d: %s; want the original answer %s", status, retry, revoked)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain the publish: %v", err)
	}
	current, err := h.store.GetCertificate(ctx, h.tenant, leaf.ID)
	if err != nil || current.Status != "revoked" || current.RevocationReason != "keyCompromise" {
		t.Fatalf("the publish did not revoke the certificate: %+v %v", current, err)
	}
	if n := eventCount(t, h.log, h.tenant, projections.EventCertificateSubjectKeyCompromised); n != 1 {
		t.Fatalf("compromised subject key events after retry and publish = %d, want 1", n)
	}
	var rows int
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM compromised_subject_keys
		WHERE tenant_id=$1 AND certificate_fingerprint=$2`, h.tenant, leaf.Fingerprint).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("compromised key rows for the certificate = %d, %v; want 1", rows, err)
	}
}

// The same window for an exact certificate revocation queued at its external
// CA: the key is recorded when the operator reports the compromise, not when
// the CA answers.
func TestServedQueuedExternalKeyCompromiseRecordsTheKeyAtOnce(t *testing.T) {
	failed, calls := true, 0
	upstream := revocationTestCA{revoke: func(_ context.Context, request ca.RevokeRequest) error {
		calls++
		if request.ReasonCode != 1 {
			t.Fatalf("revocation reached the CA with reason code %d, want keyCompromise (1)", request.ReasonCode)
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
	owner, err := h.srv.orch.CreateOwner(t.Context(), h.tenant, "service", "Queued external compromise", "")
	if err != nil {
		t.Fatal(err)
	}
	selected := recordRevocationTestLeaf(t, i, owner.ID, "queued-compromise.example.test", "retained-vault", "selected", "")
	info, err := certinfo.Inspect(selected.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", token, "queued-compromise",
		map[string]any{"certificate_ids": []string{selected.ID}, "reason": "keyCompromise"})
	if status != http.StatusOK || !bytes.Contains(raw, []byte(`"total_queued":1`)) || calls != 0 {
		t.Fatalf("external keyCompromise revocation must queue without a provider call: HTTP %d %s calls=%d", status, raw, calls)
	}
	fingerprint, recorded, err := h.store.CompromisedSubjectKey(t.Context(), h.tenant, info.SPKISHA256)
	if err != nil || !recorded || fingerprint != selected.Fingerprint {
		t.Fatalf("queued keyCompromise revocation did not record the key at once: %q %t %v", fingerprint, recorded, err)
	}
	// The CA's outage does not undo the record, and its later answer converges on it.
	row := pendingOutboxByDestination(t, i, "revocation.publish")
	message := orchestrator.Message{ID: row.ID, TenantID: h.tenant, Destination: row.Destination, Payload: row.Payload, IdempotencyKey: row.IdempotencyKey}
	if err := dispatcher.Deliver(t.Context(), message); err == nil {
		t.Fatal("issuer outage reported success")
	}
	if _, recorded, err := h.store.CompromisedSubjectKey(t.Context(), h.tenant, info.SPKISHA256); err != nil || !recorded {
		t.Fatalf("a failed CA call undid the compromised key record: %t %v", recorded, err)
	}
	failed = false
	if err := dispatcher.Deliver(t.Context(), message); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := h.store.SystemPool().QueryRow(t.Context(), `SELECT count(*) FROM compromised_subject_keys
		WHERE tenant_id=$1 AND certificate_fingerprint=$2`, h.tenant, selected.Fingerprint).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("compromised key rows for the certificate = %d, %v; want 1", rows, err)
	}
}
