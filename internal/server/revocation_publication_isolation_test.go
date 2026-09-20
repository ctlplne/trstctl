// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// A committed revocation must publish without rebuilding unrelated projections.
// Hold the real projection lock to model a busy catch-up on another replica;
// the exact certificate and CA ledger are already durably revoked.
func TestCommittedRevocationPublicationDoesNotRebuildUnrelatedProjections(t *testing.T) {
	assertCommittedPublicationIsolation(t, false)
}

func TestCommittedProtocolRevocationPublicationDoesNotRebuildUnrelatedProjections(t *testing.T) {
	assertCommittedPublicationIsolation(t, true)
}

func assertCommittedPublicationIsolation(t *testing.T, protocol bool) {
	t.Helper()
	h, owner, body := servedPublicBrokerRevocationFixture(t)
	issued := servedBrokerIssue(t, h, owner, "publication-isolation-leaf", body, http.StatusCreated)
	cert, err := h.store.GetCertificate(t.Context(), h.tenant, issued.CertificateID)
	if err != nil {
		t.Fatal(err)
	}
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", owner, "publication-isolation-revoke", map[string]any{"certificate_ids": []string{cert.ID}, "reason": "keyCompromise"})
	var result orchestrator.BulkRevokeResult
	if status != http.StatusOK || json.Unmarshal(raw, &result) != nil || result.TotalRevoked != 1 || result.TotalFailed != 0 {
		t.Fatalf("exact revocation did not commit: status=%d result=%s", status, raw)
	}
	ledger, found, err := h.store.LookupIssuedCert(t.Context(), h.tenant, IssuingCAID(), cert.Serial)
	if err != nil || !found || !ledger.Revoked() {
		t.Fatalf("revocation is not yet durable: found=%v err=%v", found, err)
	}
	rows, err := h.srv.outbox.Pending(t.Context(), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	var publication orchestrator.Message
	for _, row := range rows {
		if row.Destination == store.CertificateCRLPublicationDestination {
			if publication.ID != 0 {
				t.Fatal("more than one exact publication intent")
			}
			publication = orchestrator.Message{ID: row.ID, TenantID: h.tenant, Destination: row.Destination, Payload: row.Payload, IdempotencyKey: row.IdempotencyKey}
		}
	}
	if publication.ID == 0 {
		t.Fatal("committed revocation has no transactional publication intent")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if err := h.store.WithProjectionLock(ctx, func(locked context.Context) error {
		if protocol {
			return h.srv.newProtocolIssuer().publishTenantCRL(locked, h.tenant)
		}
		return h.srv.obHandler.Deliver(locked, publication)
	}); err != nil {
		t.Fatalf("committed revocation waited for an unrelated projection rebuild: %v", err)
	}
	status, der := secretsReq(t, h, http.MethodGet, "/crl/"+h.tenant+".crl", "", nil)
	crl, err := crypto.ParseCRL(der, h.srv.revoc.caCertDER)
	if status != http.StatusOK || err != nil || !containsSerial(crl.RevokedSerials, cert.Serial) {
		t.Fatalf("public signed CRL omitted committed revocation: status=%d err=%v", status, err)
	}
}
