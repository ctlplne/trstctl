// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestServedExactCertificateRevocationAuthorizesWholeSelectionBeforeMutation(t *testing.T) {
	h, owner, body := servedPublicBrokerRevocationFixture(t)
	first := servedBrokerIssue(t, h, owner, "whole-selection-first", body, http.StatusCreated)
	second := servedBrokerIssue(t, h, owner, "whole-selection-second", body, http.StatusCreated)
	denied := errors.New("test denies the second selected certificate")
	checked, resolved := 0, 0
	_, err := h.srv.orch.BulkRevokeCertificates(t.Context(), h.tenant, "whole-selection-command", crypto.SHA256Hex([]byte("whole-selection-request")),
		[]string{first.CertificateID, second.CertificateID}, "keyCompromise", orchestrator.CertificateRevocationChecks{
			Authorize: func(context.Context, store.Certificate) error {
				checked++
				if checked == 2 {
					return denied
				}
				return nil
			},
			Authority: func(ctx context.Context, certificate store.Certificate) (string, error) {
				resolved++
				return h.srv.certificateRevocationAuthority(ctx, certificate)
			},
		})
	if !errors.Is(err, denied) || checked != 2 || resolved != 0 || exactRevocationEventCount(t, h) != 0 || exactRevocationOutboxCount(t, h) != 0 {
		t.Fatalf("selection was not authorized before issuer work: error=%v checked=%d resolved=%d", err, checked, resolved)
	}
	for _, id := range []string{first.CertificateID, second.CertificateID} {
		certificate, err := h.store.GetCertificate(t.Context(), h.tenant, id)
		if err != nil || certificate.Status != "active" {
			t.Fatal("denial on second selection changed a selected certificate")
		}
		assertPublicCertificateOCSP(t, h, certificate.Serial, "good")
	}
}

func TestServedExactCertificateRevocationRepairsInventoryOnlyRevocation(t *testing.T) {
	h, owner, body := servedPublicBrokerRevocationFixture(t)
	issued := servedBrokerIssue(t, h, owner, "inventory-only-revocation-fixture", body, http.StatusCreated)
	certificate, err := h.store.GetCertificate(t.Context(), h.tenant, issued.CertificateID)
	if err != nil {
		t.Fatal(err)
	}
	// The legacy inventory-only event is real historical input, not a direct
	// database patch. A label alone must not become an "already revoked" proof.
	if err := h.srv.orch.RevokeCertificate(t.Context(), h.tenant, certificate.Fingerprint, certificate.Serial,
		"keyCompromise", time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	assertPublicCertificateOCSP(t, h, certificate.Serial, "good")
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", owner, "repair-inventory-only-revocation", map[string]any{
		"certificate_ids": []string{issued.CertificateID}, "reason": "cessationOfOperation",
	})
	if status != http.StatusOK || !bytes.Contains(raw, []byte(`"total_revoked":1`)) || exactRevocationOutboxCount(t, h) != 1 {
		t.Fatalf("inventory-only label was mistaken for an issuer revocation: HTTP %d %s", status, raw)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertPublicCertificateOCSP(t, h, certificate.Serial, "revoked")
	assertExactRevocationViewsAgree(t, h, issued.CertificateID)
}

func TestServedExactCertificateRevocationPreservesFirstIssuerFactsWhenReconciling(t *testing.T) {
	h, owner, body := servedPublicBrokerRevocationFixture(t)
	issued := servedBrokerIssue(t, h, owner, "first-revocation-fixture", body, http.StatusCreated)
	certificate, err := h.store.GetCertificate(t.Context(), h.tenant, issued.CertificateID)
	if err != nil {
		t.Fatal(err)
	}
	first := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	if err := h.srv.orch.RevokeCertificateForCA(t.Context(), h.tenant, certificate.Fingerprint, certificate.Serial,
		IssuingCAID(), "keyCompromise", crypto.CRLReasonCode(crypto.RevocationReasonKeyCompromise), first); err != nil {
		t.Fatal(err)
	}
	// A later legacy inventory observation must not rewrite the authority's
	// first revocation time/reason when the exact command reconciles the views.
	if err := h.srv.orch.RevokeCertificate(t.Context(), h.tenant, certificate.Fingerprint, certificate.Serial,
		"superseded", first.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	const path = "/api/v1/certificates/bulk-revoke"
	request := map[string]any{"certificate_ids": []string{issued.CertificateID}, "reason": "cessationOfOperation"}
	status, raw := secretsReqKey(t, h, http.MethodPost, path, owner, "reconcile-first-revocation", request)
	if status != http.StatusOK || !bytes.Contains(raw, []byte(`"total_revoked":1`)) {
		t.Fatalf("divergent inventory was not reconciled: HTTP %d %s", status, raw)
	}
	assertExactRevocationViewsAgree(t, h, issued.CertificateID)
	current, err := h.store.GetCertificate(t.Context(), h.tenant, issued.CertificateID)
	if err != nil || current.RevokedAt == nil || !current.RevokedAt.Equal(first) || current.RevocationReason != "keyCompromise" {
		t.Fatal("reconciliation changed the issuer's original revocation facts")
	}
	status, raw = secretsReqKey(t, h, http.MethodPost, path, owner, "already-reconciled-revocation", request)
	if status != http.StatusOK || !bytes.Contains(raw, []byte(`"total_skipped":1`)) || exactRevocationOutboxCount(t, h) != 1 {
		t.Fatalf("consistent already-revoked views were not skipped: HTTP %d %s", status, raw)
	}
}

func assertExactRevocationViewsAgree(t *testing.T, h *servedHarness, id string) {
	t.Helper()
	certificate, err := h.store.GetCertificate(t.Context(), h.tenant, id)
	if err != nil {
		t.Fatal(err)
	}
	ledger, found, err := h.store.LookupIssuedCert(t.Context(), h.tenant, IssuingCAID(), certificate.Serial)
	if err != nil || !found || !ledger.Revoked() || certificate.Status != "revoked" || certificate.RevokedAt == nil ||
		!certificate.RevokedAt.Equal(*ledger.RevokedAt) || crypto.CRLReasonCode(crypto.RevocationReason(certificate.RevocationReason)) != ledger.ReasonCode {
		t.Fatalf("inventory and issuing authority disagree: certificate=%s ledger-found=%v error=%v", certificate.Status, found, err)
	}
}

func TestServedExactCertificateRevocationSurvivesFullProjectionRebuild(t *testing.T) {
	h, owner, body := servedPublicBrokerRevocationFixture(t)
	issued := servedBrokerIssue(t, h, owner, "rebuild-revocation-fixture", body, http.StatusCreated)
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", owner, "rebuild-revocation-command", map[string]any{
		"certificate_ids": []string{issued.CertificateID}, "reason": "cessationOfOperation",
	})
	if status != http.StatusOK || !bytes.Contains(raw, []byte(`"total_revoked":1`)) {
		t.Fatalf("rebuild fixture was not revoked: HTTP %d %s", status, raw)
	}
	before, err := h.store.GetCertificate(t.Context(), h.tenant, issued.CertificateID)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("full retained-event projection rebuild: %v", err)
	}
	after, err := h.store.GetCertificate(t.Context(), h.tenant, issued.CertificateID)
	if err != nil || after.ID != before.ID || after.Fingerprint != before.Fingerprint || after.RevokedAt == nil ||
		before.RevokedAt == nil || !after.RevokedAt.Equal(*before.RevokedAt) || after.RevocationReason != before.RevocationReason {
		t.Fatalf("rebuild changed the exact retained revocation: %v", err)
	}
	assertExactRevocationViewsAgree(t, h, issued.CertificateID)
	if exactRevocationOutboxCount(t, h) != 1 || exactRevocationEventCount(t, h) != 1 {
		t.Fatal("rebuild lost or duplicated revocation/publication authority")
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertPublicCertificateOCSP(t, h, after.Serial, "revoked")
}

func TestServedExactCertificateRevocationRequiresScopeEvenWhenNothingMatches(t *testing.T) {
	h, _, _ := servedPublicBrokerRevocationFixture(t)
	writer := seedScopedToken(t, h.store, h.tenant, "identities:write")
	status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", writer, "missing-certificate-unprivileged", map[string]any{
		"certificate_ids": []string{"33333333-3333-3333-3333-333333333333"}, "reason": "keyCompromise",
	})
	if status != http.StatusForbidden || exactRevocationEventCount(t, h) != 0 || exactRevocationOutboxCount(t, h) != 0 {
		t.Fatalf("unprivileged empty selection recorded a revocation command: HTTP %d", status)
	}
}

func TestServedExactCertificateRevocationRecoversAppendBeforePublicationTransaction(t *testing.T) {
	h, owner, body := servedPublicBrokerRevocationFixture(t)
	issued := servedBrokerIssue(t, h, owner, "revocation-transaction-fixture", body, http.StatusCreated)
	certificate, err := h.store.GetCertificate(t.Context(), h.tenant, issued.CertificateID)
	if err != nil {
		t.Fatal(err)
	}
	// A deliberate database failure proves that the state and outbox intent
	// commit together. This trigger exists only in the disposable test database.
	unblock := blockExactRevocationOutbox(t, h)
	const path, key = "/api/v1/certificates/bulk-revoke", "revocation-transaction-command"
	request := map[string]any{"certificate_ids": []string{issued.CertificateID}, "reason": "cessationOfOperation"}
	status, _ := secretsReqKey(t, h, http.MethodPost, path, owner, key, request)
	if status != http.StatusInternalServerError || exactRevocationEventCount(t, h) != 1 || exactRevocationOutboxCount(t, h) != 0 {
		t.Fatalf("injected publication failure did not preserve exactly one unprojected command: HTTP %d", status)
	}
	unchanged, err := h.store.GetCertificate(t.Context(), h.tenant, issued.CertificateID)
	if err != nil || unchanged.Status != "active" {
		t.Fatal("failed outbox insertion committed certificate state")
	}
	ledger, found, err := h.store.LookupIssuedCert(t.Context(), h.tenant, IssuingCAID(), certificate.Serial)
	if err != nil || !found || ledger.Revoked() {
		t.Fatal("failed outbox insertion committed CA state")
	}
	unblock()
	status, original := secretsReqKey(t, h, http.MethodPost, path, owner, key, request)
	if status != http.StatusOK || !bytes.Contains(original, []byte(`"total_revoked":1`)) || exactRevocationEventCount(t, h) != 1 || exactRevocationOutboxCount(t, h) != 1 {
		t.Fatalf("retry did not recover the original retained command: HTTP %d %s", status, original)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertPublicCertificateOCSP(t, h, certificate.Serial, "revoked")
	// Replaying the event does not reschedule an already delivered outbox item.
	if err := h.log.Replay(t.Context(), 0, func(event events.Event) error {
		if event.Type == projections.EventCertificateRevocationBatchApplied {
			return h.srv.proj.Apply(t.Context(), event)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var delivered int
	if err := h.store.SystemPool().QueryRow(t.Context(), `SELECT count(*) FROM outbox
		WHERE tenant_id = $1 AND destination = $2 AND status = 'delivered'`,
		h.tenant, store.CertificateCRLPublicationDestination).Scan(&delivered); err != nil {
		t.Fatal(err)
	}
	if delivered != 1 || exactRevocationOutboxCount(t, h) != 1 || exactRevocationEventCount(t, h) != 1 {
		t.Fatal("event replay reset or duplicated completed publication")
	}
}

func blockExactRevocationOutbox(t *testing.T, h *servedHarness) func() {
	t.Helper()
	installed := true
	remove := func() {
		if !installed {
			return
		}
		_, err := h.store.SystemPool().Exec(context.Background(), `
			DROP TRIGGER IF EXISTS test_exact_revocation_outbox_failure ON outbox;
			DROP FUNCTION IF EXISTS test_exact_revocation_outbox_failure()`)
		if err != nil {
			t.Errorf("remove exact-revocation test trigger: %v", err)
			return
		}
		installed = false
	}
	t.Cleanup(remove)
	if _, err := h.store.SystemPool().Exec(t.Context(), `
		CREATE FUNCTION test_exact_revocation_outbox_failure() RETURNS trigger
		LANGUAGE plpgsql AS $$ BEGIN
			IF NEW.destination = 'revocation.crl.publish' THEN
				RAISE EXCEPTION 'injected exact revocation publication failure';
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER test_exact_revocation_outbox_failure BEFORE INSERT ON outbox
		FOR EACH ROW EXECUTE FUNCTION test_exact_revocation_outbox_failure()`); err != nil {
		t.Fatalf("install exact-revocation test trigger: %v", err)
	}
	return remove
}

func TestServedExactCertificateRevocationStorePrerequisites(t *testing.T) {
	h, owner, body := servedPublicBrokerRevocationFixture(t)
	issued := servedBrokerIssue(t, h, owner, "revocation-store-prerequisites", body, http.StatusCreated)
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		if _, err := h.store.LockLiveTenantRegistrationSnapshotTx(t.Context(), tx, h.tenant); err != nil {
			return err
		}
		_, err := h.store.CertificateForRevocationTx(t.Context(), tx, h.tenant, issued.CertificateID)
		return err
	}); err != nil {
		t.Fatalf("read-only tenant/certificate selection prerequisite: %v", err)
	}
}

func TestServedExactCertificateRevocationKeepsAllAuthorizationGates(t *testing.T) {
	for _, mode := range []string{"missing_scope", "policy_denial", "required_approval"} {
		t.Run(mode, func(t *testing.T) {
			h, owner, body := servedPublicBrokerRevocationFixture(t, func(d *Deps) {
				if mode == "policy_denial" {
					d.EnablePolicyGate = true
					d.PolicyModule = "package trstctl.policy\ndefault allow := false\nallow if { input.action != \"revoke\" }\n"
				}
				d.RequireApproval = mode == "required_approval"
			})
			issued := servedBrokerIssue(t, h, owner, "certificate-gate-fixture", body, http.StatusCreated)
			token := owner
			if mode == "missing_scope" {
				token = seedScopedToken(t, h.store, h.tenant, "identities:write", "certs:read")
			}
			status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", token, "certificate-gate-denied", map[string]any{
				"certificate_ids": []string{issued.CertificateID}, "reason": "keyCompromise",
			})
			if status != http.StatusForbidden {
				t.Fatalf("exact certificate path bypassed %s: HTTP %d %s", mode, status, raw)
			}
			certificate, err := h.store.GetCertificate(t.Context(), h.tenant, issued.CertificateID)
			if err != nil || certificate.Status != "active" || exactRevocationOutboxCount(t, h) != 0 {
				t.Fatalf("denied request changed certificate or publication intent: %v", err)
			}
		})
	}
}

func TestServedExactCertificateRevocationDoesNotTrustMatchingSerialOrIssuerName(t *testing.T) {
	h, owner, body := servedPublicBrokerRevocationFixture(t)
	issued := servedBrokerIssue(t, h, owner, "serial-collision-original", body, http.StatusCreated)
	original, err := h.store.GetCertificate(t.Context(), h.tenant, issued.CertificateID)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the issuer name and serial, but break the public signature. Importing
	// metadata from this observation cannot authorize revoking the real leaf.
	tampered := bytes.Clone(original.CertificateDER)
	tampered[len(tampered)-1] ^= 1
	info, err := certinfo.Inspect(tampered)
	if err != nil || info.SerialNumber != original.Serial {
		t.Fatal("fixture must remain parseable and retain the real serial")
	}
	imported, err := h.srv.orch.RecordCertificate(t.Context(), h.tenant, store.Certificate{
		Subject: info.Subject, Issuer: info.Issuer, Serial: info.SerialNumber,
		Fingerprint: info.SHA256Fingerprint, CertificateDER: tampered, Source: "imported",
	})
	if err != nil {
		t.Fatal(err)
	}
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", owner, "serial-collision-refused", map[string]any{
		"certificate_ids": []string{imported.ID}, "reason": "keyCompromise",
	})
	var result orchestrator.BulkRevokeResult
	if status != http.StatusOK || json.Unmarshal(raw, &result) != nil || result.TotalRevoked != 0 || result.TotalFailed != 1 ||
		len(result.Items) != 1 || result.Items[0].Error != projections.CertificateRevocationUnsupportedReason {
		t.Fatalf("unverified issuer was accepted or hidden: HTTP %d %s", status, raw)
	}
	for _, id := range []string{original.ID, imported.ID} {
		certificate, err := h.store.GetCertificate(t.Context(), h.tenant, id)
		if err != nil || certificate.Status != "active" {
			t.Fatal("a matching serial or issuer name changed certificate trust")
		}
	}
	ledger, found, err := h.store.LookupIssuedCert(t.Context(), h.tenant, IssuingCAID(), original.Serial)
	if err != nil || !found || ledger.Revoked() || exactRevocationOutboxCount(t, h) != 0 {
		t.Fatal("rejected imported certificate affected the real CA ledger or publisher")
	}
}

func TestServedExactCertificateRevocationRecoversOriginalResultWithoutHTTPReceipt(t *testing.T) {
	const duplicateWindow = 100 * time.Millisecond // JetStream's minimum supported window.
	h, owner, body := servedPublicBrokerRevocationFixtureWithHistoryOptions(t, []events.OpenOption{events.WithDuplicateWindowForTesting(duplicateWindow)})
	issued := servedBrokerIssue(t, h, owner, "revocation-replay-original", body, http.StatusCreated)
	request := map[string]any{"certificate_ids": []string{issued.CertificateID}, "reason": "cessationOfOperation"}
	const path, key = "/api/v1/certificates/bulk-revoke", "revocation-replay-command"
	status, original := secretsReqKey(t, h, http.MethodPost, path, owner, key, request)
	if status != http.StatusOK || !bytes.Contains(original, []byte(`"total_revoked":1`)) {
		t.Fatalf("initial exact revoke failed: HTTP %d %s", status, original)
	}
	before := exactRevocationEventCount(t, h)
	// Cross the actual JetStream duplicate-memory boundary, not a fake clock.
	// Only this isolated test has the short window; production defaults are intact.
	timer := time.NewTimer(4 * duplicateWindow)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	// Isolated negative control: lose only the disposable HTTP cache, never the
	// authoritative event or the certificate. Reuse the existing cache-GC helper.
	purgeExternalCAAPIResult(t, h, key)
	status, replay := secretsReqKey(t, h, http.MethodPost, path, owner, key, request)
	if status != http.StatusOK || !bytes.Equal(original, replay) || exactRevocationEventCount(t, h) != before || exactRevocationOutboxCount(t, h) != 1 {
		t.Fatalf("cache-loss retry changed the result, event or publication count: HTTP %d %s", status, replay)
	}
	purgeExternalCAAPIResult(t, h, key)
	request["reason"] = "keyCompromise"
	status, _ = secretsReqKey(t, h, http.MethodPost, path, owner, key, request)
	if status != http.StatusConflict || exactRevocationEventCount(t, h) != before {
		t.Fatalf("cache loss allowed changed command semantics: HTTP %d", status)
	}
}

func TestServedExactCertificateRevocationCannotReadAcrossTenantOrMixSelectors(t *testing.T) {
	h, owner, body := servedPublicBrokerRevocationFixture(t)
	issued := servedBrokerIssue(t, h, owner, "revocation-tenant-original", body, http.StatusCreated)
	const neighborTenant = "22222222-2222-2222-2222-222222222222"
	registerServedTenantID(t, h, neighborTenant, "Revocation neighbor")
	neighbor := seedScopedToken(t, h.store, neighborTenant, "identities:write", "certs:issue")
	request := map[string]any{"certificate_ids": []string{issued.CertificateID}, "reason": "keyCompromise"}
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", neighbor, "revocation-neighbor", request)
	var result orchestrator.BulkRevokeResult
	if status != http.StatusOK || json.Unmarshal(raw, &result) != nil || result.TotalMatched != 0 || result.TotalRevoked != 0 || result.TotalFailed != 1 || result.Items[0].Error != "not found" {
		t.Fatalf("cross-tenant selection disclosed or changed a credential: HTTP %d %s", status, raw)
	}
	for _, field := range []string{"identity_ids", "owner_id", "issuer_id", "kind", "status"} {
		if field == "identity_ids" {
			request[field] = []string{issued.CertificateID}
		} else {
			request[field] = "not-an-exact-certificate-selector"
		}
		status, _ = secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", owner, "revocation-mixed-"+field, request)
		if status != http.StatusBadRequest {
			t.Fatalf("mixed %s selector was not refused: HTTP %d", field, status)
		}
		delete(request, field)
	}
	status, _ = secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", owner, "revocation-empty-exact-selection", map[string]any{
		"certificate_ids": []string{}, "identity_ids": []string{issued.CertificateID}, "reason": "keyCompromise",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("empty certificate selection fell through to identity selection: HTTP %d", status)
	}
	request["reason"] = "removeFromCRL"
	status, _ = secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", owner, "revocation-not-unhold", request)
	if status != http.StatusBadRequest {
		t.Fatalf("permanent revocation accepted a remove-from-CRL operation: HTTP %d", status)
	}
	certificate, err := h.store.GetCertificate(t.Context(), h.tenant, issued.CertificateID)
	if err != nil || certificate.Status != "active" || exactRevocationOutboxCount(t, h) != 0 {
		t.Fatal("denied selectors or tenant access changed the original")
	}
}

func exactRevocationOutboxCount(t *testing.T, h *servedHarness) int {
	t.Helper()
	var count int
	if err := h.store.SystemPool().QueryRow(t.Context(), `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = $2`,
		h.tenant, store.CertificateCRLPublicationDestination).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func exactRevocationEventCount(t *testing.T, h *servedHarness) int {
	t.Helper()
	count := 0
	if err := h.log.Replay(t.Context(), 0, func(event events.Event) error {
		if event.TenantID == h.tenant && event.Type == projections.EventCertificateRevocationBatchApplied {
			count++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return count
}
