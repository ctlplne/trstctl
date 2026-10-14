// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestServedRetainedCertificateRevocationNeverSignsGoodOCSP(t *testing.T) {
	h, owner, body := servedPublicBrokerRevocationFixture(t)
	issued := servedBrokerIssue(t, h, owner, "terminal-ocsp-gap", body, http.StatusCreated)
	certificate, err := h.store.GetCertificate(t.Context(), h.tenant, issued.CertificateID)
	if err != nil {
		t.Fatal(err)
	}
	assertPublicCertificateOCSP(t, h, certificate.Serial, "good")
	unblock := blockExactRevocationOutbox(t, h)
	status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", owner,
		"terminal-ocsp-gap-revoke", map[string]any{
			"certificate_ids": []string{issued.CertificateID}, "reason": "keyCompromise",
		})
	if status != http.StatusInternalServerError || exactRevocationEventCount(t, h) != 1 {
		t.Fatalf("fault did not retain one revoke: HTTP %d events=%d", status, exactRevocationEventCount(t, h))
	}
	ledger, found, err := h.store.LookupIssuedCert(t.Context(), h.tenant, IssuingCAID(), certificate.Serial)
	if err != nil || !found || ledger.Revoked() {
		t.Fatalf("fault precondition: stale issuer ledger = %+v found=%t err=%v", ledger, found, err)
	}
	readStatus, readBody := secretsReq(t, h, http.MethodGet, "/api/v1/certificates/"+issued.CertificateID, owner, nil)
	if readStatus != http.StatusOK || !bytes.Contains(readBody, []byte(`"revocation_pending":true`)) {
		t.Fatalf("inventory concealed accepted revocation during projection failure: HTTP %d %s", readStatus, readBody)
	}
	listStatus, listBody := secretsReq(t, h, http.MethodGet, "/api/v1/certificates", owner, nil)
	if listStatus != http.StatusOK || !bytes.Contains(listBody, []byte(`"revocation_pending":true`)) {
		t.Fatalf("inventory list concealed accepted revocation: HTTP %d %s", listStatus, listBody)
	}
	requestDER, err := crypto.BuildOCSPRequestForSerial(h.srv.agentBroker.caCertDER, certificate.Serial)
	if err != nil {
		t.Fatal(err)
	}
	responseDER, err := h.srv.OCSPResponse(t.Context(), h.tenant, requestDER)
	if err == nil {
		parsed, parseErr := crypto.ParseOCSPResponse(responseDER, h.srv.agentBroker.caCertDER)
		if parseErr == nil && parsed.Status == "good" {
			t.Fatal("retained certificate revocation signed a false Good OCSP response")
		}
	}
	unblock()
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", owner,
		"terminal-ocsp-gap-revoke", map[string]any{
			"certificate_ids": []string{issued.CertificateID}, "reason": "keyCompromise",
		})
	if status != http.StatusOK || !bytes.Contains(raw, []byte(`"total_revoked":1`)) {
		t.Fatalf("exact retained command recovery = HTTP %d %s", status, raw)
	}
	assertPublicCertificateOCSP(t, h, certificate.Serial, "revoked")
	readStatus, readBody = secretsReq(t, h, http.MethodGet, "/api/v1/certificates/"+issued.CertificateID, owner, nil)
	if readStatus != http.StatusOK || !bytes.Contains(readBody, []byte(`"revocation_pending":false`)) {
		t.Fatalf("inventory still showed pending after recovery: HTTP %d %s", readStatus, readBody)
	}
}

func TestServedProjectedRevocationWaitsForFreshSignedCRL(t *testing.T) {
	h, owner, body := servedPublicBrokerRevocationFixture(t)
	issued := servedBrokerIssue(t, h, owner, "terminal-crl-publication-gap", body, http.StatusCreated)
	certificate, err := h.store.GetCertificate(t.Context(), h.tenant, issued.CertificateID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.revoc.servedCRL(t.Context(), h.tenant); err != nil {
		t.Fatalf("initial signed CRL: %v", err)
	}
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", owner,
		"terminal-crl-publication-gap-revoke", map[string]any{
			"certificate_ids": []string{issued.CertificateID}, "reason": "keyCompromise",
		})
	if status != http.StatusOK || !bytes.Contains(raw, []byte(`"total_revoked":1`)) {
		t.Fatalf("exact revocation = HTTP %d %s", status, raw)
	}
	if _, err := h.srv.revoc.servedCRL(t.Context(), h.tenant); err == nil {
		t.Fatal("projected revocation served the predecessor CRL before publication")
	}
	rows, err := h.srv.outbox.Pending(t.Context(), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	var publication orchestrator.Message
	for _, row := range rows {
		if row.Destination == store.CertificateCRLPublicationDestination {
			publication = orchestrator.Message{ID: row.ID, TenantID: h.tenant, Destination: row.Destination,
				Payload: row.Payload, IdempotencyKey: row.IdempotencyKey}
		}
	}
	if publication.ID == 0 {
		t.Fatal("revocation has no publication intent")
	}
	if err := h.srv.obHandler.Deliver(t.Context(), publication); err != nil {
		t.Fatalf("publish signed CRL: %v", err)
	}
	der, err := h.srv.revoc.servedCRL(t.Context(), h.tenant)
	if err != nil {
		t.Fatalf("fresh signed CRL: %v", err)
	}
	crl, err := crypto.ParseCRL(der, h.srv.revoc.caCertDER)
	if err != nil || !containsSerial(crl.RevokedSerials, certificate.Serial) {
		t.Fatalf("fresh signed CRL omitted revoked issuer serial: %v", err)
	}
}

func TestServedDirectCertificateRevocationFencesStatusDuringProjectionGap(t *testing.T) {
	h, owner, body := servedPublicBrokerRevocationFixture(t)
	issued := servedBrokerIssue(t, h, owner, "direct-terminal-status", body, http.StatusCreated)
	certificate, err := h.store.GetCertificate(t.Context(), h.tenant, issued.CertificateID)
	if err != nil {
		t.Fatal(err)
	}
	assertPublicCertificateOCSP(t, h, certificate.Serial, "good")
	const trigger = "qa_direct_certificate_projection_fail"
	const function = "qa_direct_certificate_projection_fail_fn"
	clearFault := func() {
		_, err := h.store.SystemPool().Exec(context.Background(),
			"DROP TRIGGER IF EXISTS "+trigger+" ON ca_issued_certs; DROP FUNCTION IF EXISTS "+function+"()")
		if err != nil {
			t.Errorf("clear direct issuer fault: %v", err)
		}
	}
	t.Cleanup(clearFault)
	_, err = h.store.SystemPool().Exec(t.Context(), fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger
		LANGUAGE plpgsql AS $$ BEGIN
			IF NEW.serial = '%s' AND NEW.revoked_at IS NOT NULL THEN
				RAISE EXCEPTION 'qa injected direct issuer projection outage';
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER %s BEFORE UPDATE ON ca_issued_certs
		FOR EACH ROW EXECUTE FUNCTION %s()`, function, certificate.Serial, trigger, function))
	if err != nil {
		t.Fatal(err)
	}
	eventID := "direct-terminal-" + crypto.SHA256Hex([]byte(certificate.Fingerprint))[:16]
	if err := h.srv.orch.RevokeCertificateForCAWithEventID(t.Context(), h.tenant, eventID,
		certificate.Fingerprint, certificate.Serial, IssuingCAID(), "keyCompromise",
		crypto.CRLReasonCode(crypto.RevocationReasonKeyCompromise)); err == nil {
		t.Fatal("direct revoke reported success despite failed issuer projection")
	}
	if event, found, err := h.log.EventByID(t.Context(), eventID); err != nil || !found || event.Type != projections.EventCertificateRevoked {
		t.Fatalf("direct issuer event was not retained: found=%t event=%+v err=%v", found, event, err)
	}
	requestDER, err := crypto.BuildOCSPRequestForSerial(h.srv.agentBroker.caCertDER, certificate.Serial)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.OCSPResponse(t.Context(), h.tenant, requestDER); err == nil {
		t.Fatal("retained direct certificate revoke served cached Good OCSP")
	}
	clearFault()
	if healed, err := reconcilePendingCertificateRevocationAuthority(t.Context(), h.store, h.log); err != nil || healed != 1 {
		t.Fatalf("direct issuer recovery = %d, %v", healed, err)
	}
	assertPublicCertificateOCSP(t, h, certificate.Serial, "revoked")
}

func TestServedPreappendCertificateRevocationFencesOCSPAndCRL(t *testing.T) {
	h, owner, body := servedPublicBrokerRevocationFixture(t)
	issued := servedBrokerIssue(t, h, owner, "preappend-status-fence", body, http.StatusCreated)
	certificate, err := h.store.GetCertificate(t.Context(), h.tenant, issued.CertificateID)
	if err != nil {
		t.Fatal(err)
	}
	assertPublicCertificateOCSP(t, h, certificate.Serial, "good")
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	batch := projections.CertificateRevocationBatchApplied{
		RequestBinding: crypto.SHA256Hex([]byte("preappend certificate revocation")),
		Reason:         "keyCompromise",
		Items: []projections.CertificateRevocationItem{{
			ID: issued.CertificateID, Matched: true, Status: "revoked",
			CAID: IssuingCAID(), Serial: certificate.Serial, Fingerprint: certificate.Fingerprint,
		}},
	}
	payload, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	first := store.CertificateRevocationAuthorityCommand{
		Event: events.Event{ID: "certificate-revocation-preappend-test", Type: projections.EventCertificateRevocationBatchApplied,
			TenantID: h.tenant, Time: time.Now().UTC().Truncate(time.Microsecond),
			SchemaVersion: events.DefaultSchemaVersion, Data: payload},
		RequestBinding: batch.RequestBinding,
		Targets: []store.CertificateRevocationAuthorityTarget{{
			CAID: IssuingCAID(), Serial: certificate.Serial, Fingerprint: certificate.Fingerprint,
		}},
	}
	if _, err := h.store.ClaimCertificateRevocationAuthority(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if _, found, err := h.log.EventByID(t.Context(), first.Event.ID); err != nil || found {
		t.Fatalf("preappend fixture unexpectedly has an event: found=%t err=%v", found, err)
	}
	requestDER, err := crypto.BuildOCSPRequestForSerial(h.srv.agentBroker.caCertDER, certificate.Serial)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.OCSPResponse(t.Context(), h.tenant, requestDER); err == nil {
		t.Fatal("preappend certificate revocation served cached Good OCSP")
	}
	if _, err := h.srv.revoc.servedCRL(t.Context(), h.tenant); err == nil {
		t.Fatal("preappend certificate revocation served a stale CRL")
	}
	other := first
	other.Event.ID = "certificate-revocation-competing-test"
	if _, err := h.store.ClaimCertificateRevocationAuthority(t.Context(), other); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("competing issuer command displaced first writer: %v", err)
	}
	other = first
	other.Targets = []store.CertificateRevocationAuthorityTarget{{
		CAID: IssuingCAID(), Serial: certificate.Serial, Fingerprint: crypto.SHA256Hex([]byte("different public leaf")),
	}}
	if _, err := h.store.ClaimCertificateRevocationAuthority(t.Context(), other); !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("same event ID substituted a different issuer target: %v", err)
	}
	if healed, err := reconcilePendingCertificateRevocationAuthority(t.Context(), h.store, h.log); err != nil || healed != 1 {
		t.Fatalf("preappend issuer recovery = %d, %v", healed, err)
	}
	if healed, err := reconcilePendingCertificateRevocationAuthority(t.Context(), h.store, h.log); err != nil || healed != 0 {
		t.Fatalf("repeated issuer recovery = %d, %v", healed, err)
	}
	assertPublicCertificateOCSP(t, h, certificate.Serial, "revoked")
}
