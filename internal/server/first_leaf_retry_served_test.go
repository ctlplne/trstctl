// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"

	"github.com/jackc/pgx/v5"
)

// Use the actual HTTP surface, PostgreSQL, NATS, and UDS signing fixture. A
// signature whose recording failed must be recoverable after the automatic
// delivery budget is exhausted, without changing the original command or key.
func TestServedFirstLeafCanRequestOneAuditedRetry(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	ctx := t.Context()
	token := seedScopedToken(t, h.store, h.tenant, "owners:read", "owners:write", "identities:read", "identities:write", "certs:read", "certs:issue")
	owner := servedCreateID(t, h, token, "retry-owner", "/api/v1/owners", map[string]any{
		"kind": "service", "name": "retry-owner", "email": "retry-owner@example.test",
		"application_id": "retry-first-leaf", "environment": "test",
	})
	identity := servedCreateID(t, h, token, "retry-identity", "/api/v1/identities", map[string]any{
		"kind": "x509_certificate", "name": "retry-first-leaf.example.test", "owner_id": owner,
	})
	const requestKey = "retry-first-leaf-issuance"
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+identity+"/transitions", token, requestKey,
		map[string]any{"to": "issued", "reason": "first certificate recovery qualification"})
	if status != http.StatusOK {
		t.Fatalf("issue transition: %d %s", status, body)
	}
	d := h.srv.obHandler.(*issuanceDispatcher)
	issue := d.issue
	var signedDER []byte
	d.issue = func(ctx context.Context, csr []byte, ttl time.Duration, profile crypto.LeafProfile) (crypto.IssuedLeaf, error) {
		leaf, err := issue(ctx, csr, ttl, profile)
		if err != nil {
			return leaf, err
		}
		signedDER = append([]byte(nil), leaf.DER...)
		return crypto.IssuedLeaf{}, errors.New("QA: original signature reply lost before inventory recording")
	}
	box := orchestrator.NewOutbox(h.store, orchestrator.WithMaxAttempts(1))
	did, err := box.DispatchOneScoped(ctx, d, orchestrator.DestinationScope{IncludePrefixes: []string{"ca.issue"}})
	if err != nil || !did || len(signedDER) == 0 {
		t.Fatalf("create exhausted signed issuance: dispatched=%t signed=%t err=%v", did, len(signedDER) > 0, err)
	}
	before, err := h.store.GetIdentityIssuanceResult(ctx, h.tenant, identity, requestKey)
	if err != nil || before.Certificate != nil || before.Delivery == nil || before.Delivery.Status != "failed" || before.Delivery.Attempts != 1 {
		t.Fatalf("failed original issuance was not preserved: %+v %v", before, err)
	}
	d.issue = issue
	retryPath := "/api/v1/identities/" + identity + "/issuance-retry"
	retryRequest := map[string]any{"request_key": requestKey, "reason": "recording dependency restored; recover original signed certificate"}
	status, receipt := secretsReqKey(t, h, http.MethodPost, retryPath, token, "retry-grant-once", retryRequest)
	if status != http.StatusAccepted {
		t.Fatalf("operator cannot request safe retry: status=%d body=%s", status, receipt)
	}
	status, replay := secretsReqKey(t, h, http.MethodPost, retryPath, token, "retry-grant-once", retryRequest)
	if status != http.StatusAccepted || !bytes.Equal(receipt, replay) {
		t.Fatalf("retry request replay changed its receipt: %d %s", status, replay)
	}
	did, err = box.DispatchOneScoped(ctx, d, orchestrator.DestinationScope{IncludePrefixes: []string{"ca.issue"}})
	if err != nil || !did {
		t.Fatalf("retry was not claimable: %t %v", did, err)
	}
	after, err := h.store.GetIdentityIssuanceResult(ctx, h.tenant, identity, requestKey)
	if err != nil || after.Certificate == nil || after.Delivery == nil || after.Delivery.Status != "delivered" || after.Delivery.Attempts != 2 ||
		!bytes.Equal(after.Certificate.CertificateDER, signedDER) {
		t.Fatalf("retry did not preserve original certificate and cumulative attempts: %+v %v", after.Delivery, err)
	}
	if err := projections.New(h.store).Rebuild(ctx, h.log); err != nil {
		t.Fatal(err)
	}
	afterReplay, err := h.store.GetIdentityIssuanceResult(ctx, h.tenant, identity, requestKey)
	if err != nil || afterReplay.Delivery == nil || afterReplay.Delivery.Status != "delivered" || afterReplay.Delivery.Attempts != 2 {
		t.Fatalf("source replay granted another attempt: %+v %v", afterReplay.Delivery, err)
	}
	counts := tenantEventTypes(t, h.log, h.tenant)
	if counts["issuance.retry_requested"] != 1 || counts["certificate.recorded"] != 1 {
		encoded, _ := json.Marshal(counts)
		t.Fatalf("recovery duplicated source facts: %s", encoded)
	}
}

func TestServedFirstLeafRetryRefusesUnsafeRequestsAndNeverRefundsAnAttempt(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	ctx := t.Context()
	token := seedScopedToken(t, h.store, h.tenant, "owners:read", "owners:write", "identities:read", "identities:write", "certs:read", "certs:issue")
	reader := seedScopedToken(t, h.store, h.tenant, "identities:read", "certs:read")
	otherTenant := seedScopedToken(t, h.store, "22222222-2222-2222-2222-222222222222", "identities:read", "certs:read", "certs:issue")
	owner := servedCreateID(t, h, token, "retry-guards-owner", "/api/v1/owners", map[string]any{
		"kind": "service", "name": "retry-guards-owner", "email": "retry-guards@example.test",
		"application_id": "retry-guards", "environment": "test",
	})
	d := h.srv.obHandler.(*issuanceDispatcher)
	issue := d.issue
	t.Cleanup(func() { d.issue = issue })
	scope := orchestrator.DestinationScope{IncludePrefixes: []string{"ca.issue"}}
	dispatch := func(maxAttempts int) {
		t.Helper()
		did, err := orchestrator.NewOutbox(h.store, orchestrator.WithMaxAttempts(maxAttempts)).DispatchOneScoped(ctx, d, scope)
		if err != nil || !did {
			t.Fatalf("dispatch: did=%t err=%v", did, err)
		}
	}
	makeFailed := func(label string, retainSignature bool) (string, string, string) {
		t.Helper()
		identity := servedCreateID(t, h, token, label+"-identity", "/api/v1/identities", map[string]any{
			"kind": "x509_certificate", "name": label + ".example.test", "owner_id": owner,
		})
		key := label + "-issue"
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+identity+"/transitions", token, key, map[string]any{"to": "issued", "reason": "retry safety qualification"})
		if status != http.StatusOK {
			t.Fatalf("issue: %d %s", status, body)
		}
		d.issue = func(ctx context.Context, csr []byte, ttl time.Duration, profile crypto.LeafProfile) (crypto.IssuedLeaf, error) {
			if retainSignature {
				if _, err := issue(ctx, csr, ttl, profile); err != nil {
					return crypto.IssuedLeaf{}, err
				}
			}
			return crypto.IssuedLeaf{}, errors.New("QA: reply unavailable")
		}
		dispatch(1)
		d.issue = issue
		return identity, key, "/api/v1/identities/" + identity + "/issuance-retry"
	}
	assertDelivery := func(identity, key, status string, attempts int) {
		t.Helper()
		result, err := h.store.GetIdentityIssuanceResult(ctx, h.tenant, identity, key)
		if err != nil || result.Delivery == nil || result.Delivery.Status != status || result.Delivery.Attempts != attempts {
			t.Fatalf("delivery want %s/%d: %+v err=%v", status, attempts, result, err)
		}
	}
	readiness := func(identity, key string, allowed bool) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+identity+"/issuance-result?request_key="+key, token, nil)
		var result struct {
			Retry *struct {
				Allowed bool   `json:"allowed"`
				Reason  string `json:"reason"`
			} `json:"retry"`
		}
		if err := json.Unmarshal(body, &result); err != nil || status != http.StatusOK || result.Retry == nil || result.Retry.Allowed != allowed || result.Retry.Reason == "" {
			t.Fatalf("readiness want %t: %d %s err=%v", allowed, status, body, err)
		}
	}

	t.Run("missing signing evidence refuses recovery", func(t *testing.T) {
		identity, key, path := makeFailed("unprepared-retry", false)
		readiness(identity, key, false)
		before := tenantEventTypes(t, h.log, h.tenant)["issuance.retry_requested"]
		status, body := secretsReqKey(t, h, http.MethodPost, path, token, "unprepared-grant", map[string]any{"request_key": key, "reason": "dependency restored"})
		if status != http.StatusConflict || !strings.Contains(string(body), "no retained signing operation") {
			t.Fatalf("unprepared request was not refused: %d %s", status, body)
		}
		assertDelivery(identity, key, "failed", 1)
		if tenantEventTypes(t, h.log, h.tenant)["issuance.retry_requested"] != before {
			t.Fatal("refused request appended a grant")
		}
	})

	t.Run("authorization binding and one attempt ceiling", func(t *testing.T) {
		identity, key, path := makeFailed("bounded-retry", true)
		readiness(identity, key, true)
		body := map[string]any{"request_key": key, "reason": "recording service restored"}
		for i, tc := range []struct {
			token  string
			status int
		}{{"", http.StatusUnauthorized}, {reader, http.StatusForbidden}, {otherTenant, http.StatusNotFound}} {
			status, response := secretsReqKey(t, h, http.MethodPost, path, tc.token, fmt.Sprintf("denied-grant-%d", i), body)
			if status != tc.status {
				t.Fatalf("unauthorized grant %d: %d %s", i, status, response)
			}
		}
		status, response := secretsReqKey(t, h, http.MethodPost, path, token, "wrong-request-grant", map[string]any{"request_key": "different-original", "reason": "restored"})
		if status != http.StatusConflict {
			t.Fatalf("wrong command grant: %d %s", status, response)
		}
		assertDelivery(identity, key, "failed", 1)
		status, receipt := secretsReqKey(t, h, http.MethodPost, path, token, "bounded-grant", body)
		if status != http.StatusAccepted {
			t.Fatalf("grant: %d %s", status, receipt)
		}
		otherActor := seedScopedTokenSubject(t, h.store, h.tenant, "another-recovery-operator", "certs:issue")
		status, response = secretsReqKey(t, h, http.MethodPost, path, otherActor, "bounded-grant", body)
		if status != http.StatusConflict {
			t.Fatalf("different actor reused grant receipt: %d %s", status, response)
		}
		status, response = secretsReqKey(t, h, http.MethodPost, path, token, "bounded-grant", map[string]any{"request_key": key, "reason": "changed justification"})
		if status != http.StatusConflict {
			t.Fatalf("changed body reused grant key: %d %s", status, response)
		}
		status, response = secretsReqKey(t, h, http.MethodPost, path, token, "concurrent-grant", body)
		if status != http.StatusConflict {
			t.Fatalf("pending request got another grant: %d %s", status, response)
		}
		// A newer worker's larger automatic allowance must not enlarge this grant.
		d.issue = func(context.Context, []byte, time.Duration, crypto.LeafProfile) (crypto.IssuedLeaf, error) {
			return crypto.IssuedLeaf{}, errors.New("QA: recording dependency still unavailable")
		}
		dispatch(10)
		d.issue = issue
		assertDelivery(identity, key, "failed", 2)
		status, replay := secretsReqKey(t, h, http.MethodPost, path, token, "bounded-grant", body)
		if status != http.StatusAccepted || !bytes.Equal(receipt, replay) {
			t.Fatalf("consumed receipt changed: %d %s", status, replay)
		}
		assertDelivery(identity, key, "failed", 2)
		if err := projections.New(h.store).Rebuild(ctx, h.log); err != nil {
			t.Fatal(err)
		}
		assertDelivery(identity, key, "failed", 2)
		status, response = secretsReqKey(t, h, http.MethodPost, path, token, "second-explicit-grant", body)
		if status != http.StatusAccepted {
			t.Fatalf("second explicit recovery: %d %s", status, response)
		}
		dispatch(10)
		assertDelivery(identity, key, "delivered", 3)
	})

	t.Run("lifecycle advancement fences queued signing and replay accepts erased reason", func(t *testing.T) {
		identity, key, path := makeFailed("revoked-retry", true)
		status, body := secretsReqKey(t, h, http.MethodPost, path, token, "revoked-grant", map[string]any{"request_key": key, "reason": "dependency restored"})
		if status != http.StatusAccepted {
			t.Fatalf("grant: %d %s", status, body)
		}
		var response struct {
			EventID string `json:"retry_event_id"`
		}
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatal(err)
		}
		event, found, err := h.log.EventByID(ctx, response.EventID)
		if err != nil || !found {
			t.Fatalf("missing source grant: %t %v", found, err)
		}
		var receipt store.FirstIssuanceRetryReceipt
		if err := json.Unmarshal(event.Data, &receipt); err != nil {
			t.Fatal(err)
		}
		receipt.Reason = "" // Privacy erasure may clear free text, never grant authority.
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error { return h.store.ApplyFirstIssuanceRetryRequestedTx(ctx, tx, h.tenant, receipt) }); err != nil {
			t.Fatal(err)
		}
		receipt.ProofKind = "assume-safe"
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error { return h.store.ApplyFirstIssuanceRetryRequestedTx(ctx, tx, h.tenant, receipt) }); err == nil {
			t.Fatal("unknown recovery proof accepted on replay")
		}
		receipt.ProofKind, receipt.OriginalPayloadSHA256 = "prepared_signing_operation", strings.Repeat("0", 64)
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error { return h.store.ApplyFirstIssuanceRetryRequestedTx(ctx, tx, h.tenant, receipt) }); !errors.Is(err, store.ErrIdempotencyConflict) {
			t.Fatalf("changed receiver command accepted: %v", err)
		}
		status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+identity+"/transitions", token, "revoke-before-retry", map[string]any{"to": "revoked", "reason": "keyCompromise"})
		if status != http.StatusOK {
			t.Fatalf("revoke before recovery: %d %s", status, body)
		}
		signed := 0
		d.issue = func(context.Context, []byte, time.Duration, crypto.LeafProfile) (crypto.IssuedLeaf, error) {
			signed++
			return crypto.IssuedLeaf{}, errors.New("must not sign a revoked identity")
		}
		// Revocation cancels the queued retry before a signer can claim it.
		// The granted allowance is not a consumed attempt and must not be
		// rewritten as a signing failure after the lifecycle has stopped.
		assertDelivery(identity, key, "cancelled", 1)
		did, err := orchestrator.NewOutbox(h.store, orchestrator.WithMaxAttempts(10)).DispatchOneScoped(ctx, d, scope)
		if err != nil || did {
			t.Fatalf("revoked retry remained dispatchable: did=%t err=%v", did, err)
		}
		d.issue = issue
		if signed != 0 {
			t.Fatal("queued retry called signer after identity was revoked")
		}
		assertDelivery(identity, key, "cancelled", 1)
		readiness(identity, key, false)
		status, cancelledBody := secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+identity+"/issuance-result?request_key="+key, token, nil)
		var cancelled struct {
			State       string           `json:"state"`
			Certificate *json.RawMessage `json:"certificate"`
			Delivery    struct {
				Status   string `json:"status"`
				Attempts int    `json:"attempts"`
			} `json:"delivery"`
		}
		if err := json.Unmarshal(cancelledBody, &cancelled); err != nil || status != http.StatusOK || cancelled.State != "cancelled" || cancelled.Delivery.Status != "cancelled" || cancelled.Delivery.Attempts != 1 || cancelled.Certificate != nil {
			t.Fatalf("cancelled issuance was not a terminal public result: %d %s err=%v", status, cancelledBody, err)
		}
		status, retryBody := secretsReqKey(t, h, http.MethodPost, path, token, "cancelled-new-grant", map[string]any{"request_key": key, "reason": "must not restart revoked work"})
		if status != http.StatusConflict {
			t.Fatalf("cancelled issuance accepted a retry: %d %s", status, retryBody)
		}
		if err := projections.New(h.store).Rebuild(ctx, h.log); err != nil {
			t.Fatal(err)
		}
		assertDelivery(identity, key, "cancelled", 1)
		readiness(identity, key, false)
	})

	t.Run("source append survives a lost SQL commit", func(t *testing.T) {
		identity, key, path := makeFailed("lost-commit-retry", true)
		before := tenantEventTypes(t, h.log, h.tenant)["issuance.retry_requested"]
		// This fault is restricted to this test's database, not a running stack.
		_, err := h.store.SystemPool().Exec(ctx, `CREATE FUNCTION retry_commit_gap() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.status='failed' AND NEW.status='pending' THEN RAISE EXCEPTION 'owned retry commit gap'; END IF; RETURN NEW; END $$;
CREATE TRIGGER retry_commit_gap BEFORE UPDATE ON outbox FOR EACH ROW EXECUTE FUNCTION retry_commit_gap()`)
		if err != nil {
			t.Fatal(err)
		}
		cleanup := func() {
			_, err := h.store.SystemPool().Exec(ctx, `DROP TRIGGER IF EXISTS retry_commit_gap ON outbox; DROP FUNCTION IF EXISTS retry_commit_gap()`)
			if err != nil {
				t.Fatal(err)
			}
		}
		t.Cleanup(cleanup)
		body := map[string]any{"request_key": key, "reason": "recording service restored"}
		status, response := secretsReqKey(t, h, http.MethodPost, path, token, "lost-commit-grant", body)
		if status < 500 {
			t.Fatalf("fault did not abort grant projection: %d %s", status, response)
		}
		assertDelivery(identity, key, "failed", 1)
		if tenantEventTypes(t, h.log, h.tenant)["issuance.retry_requested"] != before+1 {
			t.Fatal("source grant was not durably appended")
		}
		cleanup()
		status, response = secretsReqKey(t, h, http.MethodPost, path, token, "lost-commit-grant", body)
		if status != http.StatusAccepted {
			t.Fatalf("retained grant did not recover SQL projection: %d %s", status, response)
		}
		assertDelivery(identity, key, "pending", 1)
		if tenantEventTypes(t, h.log, h.tenant)["issuance.retry_requested"] != before+1 {
			t.Fatal("SQL recovery duplicated source grant")
		}
		dispatch(10)
		assertDelivery(identity, key, "delivered", 2)
	})
}
