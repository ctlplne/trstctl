// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
)

func TestServedFirstLeafResultReportsExhaustedDelivery(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "owners:write", "identities:write", "certs:read", "certs:issue")
	owner := servedCreateID(t, h, token, "failed-leaf-owner", "/api/v1/owners", map[string]any{
		"kind": "workload", "name": "failed-leaf", "email": "owner@example.test",
		"application_id": "failed-leaf", "environment": "test",
	})
	id := servedCreateID(t, h, token, "failed-leaf-identity", "/api/v1/identities", map[string]any{
		"kind": "x509_certificate", "name": "failed-leaf.example.test", "owner_id": owner,
	})
	const requestKey = "failed-leaf-transition"
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+id+"/transitions", token, requestKey, map[string]any{
		"to": "issued", "reason": "exercise terminal delivery evidence",
	})
	if status != http.StatusOK {
		t.Fatalf("accept issuance: %d %s", status, body)
	}
	// The actual worker claims and exhausts the real tenant outbox command.
	// The injected pre-I/O failure avoids contacting a CA; no status row is
	// rewritten to manufacture a failure and no certificate is fabricated.
	box := orchestrator.NewOutbox(h.store, orchestrator.WithMaxAttempts(1))
	delivered, err := box.DispatchOneScoped(t.Context(), orchestrator.HandlerFunc(func(_ context.Context, m orchestrator.Message) error {
		if m.TenantID != h.tenant || m.IdempotencyKey != "transition:"+requestKey || m.Attempts != 1 {
			t.Errorf("wrong issuance command delivered: tenant=%s key=%s attempts=%d", m.TenantID, m.IdempotencyKey, m.Attempts)
		}
		return errors.New("private-provider-diagnostic-must-not-be-returned")
	}), orchestrator.DestinationScope{IncludePrefixes: []string{"ca.issue"}})
	if err != nil || !delivered {
		t.Fatalf("exhaust real command: %t %v", delivered, err)
	}
	before, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/identities/" + id + "/issuance-result?request_key=" + requestKey
	for range 2 {
		status, body = secretsReq(t, h, http.MethodGet, path, token, nil)
		var result struct {
			State       string          `json:"state"`
			Certificate json.RawMessage `json:"certificate"`
			PEM         string          `json:"certificate_pem"`
			Delivery    struct {
				Status   string `json:"status"`
				Attempts int    `json:"attempts"`
			} `json:"delivery"`
		}
		if err := json.Unmarshal(body, &result); err != nil || status != http.StatusOK || result.State != "failed" ||
			result.Delivery.Status != "failed" || result.Delivery.Attempts != 1 || len(result.Certificate) != 0 || result.PEM != "" {
			t.Fatalf("terminal command still appears pending: %d %s err=%v", status, body, err)
		}
		if strings.Contains(string(body), "private-provider-diagnostic") {
			t.Fatal("result leaked the receiver diagnostic")
		}
	}
	if after, err := h.log.LastSequence(t.Context()); err != nil || before != after {
		t.Fatalf("reading failure changed source history: %d -> %d, %v", before, after, err)
	}
	// Deliberate missing-bookkeeping fixture: absence cannot become an
	// assertion that a command is queued, nor authorize another mutation.
	if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `DELETE FROM outbox WHERE tenant_id=$1 AND idempotency_key=$2`, h.tenant, "transition:"+requestKey)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, h, http.MethodGet, path, token, nil)
	var missing struct {
		State    string          `json:"state"`
		Delivery json.RawMessage `json:"delivery"`
	}
	if err := json.Unmarshal(body, &missing); err != nil || status != http.StatusOK || missing.State != "unavailable" || len(missing.Delivery) != 0 {
		t.Fatalf("missing command misreported: %d %s, %v", status, body, err)
	}
}

func TestServedFirstLeafRecordedCertificateSurvivesLateDeliveryFailure(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "owners:write", "identities:write", "certs:read", "certs:issue")
	owner := servedCreateID(t, h, token, "late-failure-owner", "/api/v1/owners", map[string]any{
		"kind": "workload", "name": "late-failure", "email": "owner@example.test",
		"application_id": "late-failure", "environment": "test",
	})
	id := servedCreateID(t, h, token, "late-failure-identity", "/api/v1/identities", map[string]any{
		"kind": "x509_certificate", "name": "late-failure.example.test", "owner_id": owner,
	})
	const requestKey = "late-failure-transition"
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+id+"/transitions", token, requestKey, map[string]any{
		"to": "issued", "subject_csr_pem": string(subjectCSR(t, "late-failure.example.test")),
	})
	if status != http.StatusOK {
		t.Fatalf("accept issuance: %d %s", status, body)
	}
	box := orchestrator.NewOutbox(h.store, orchestrator.WithMaxAttempts(1))
	delivered, err := box.DispatchOneScoped(t.Context(), orchestrator.HandlerFunc(func(ctx context.Context, m orchestrator.Message) error {
		if err := h.srv.obHandler.Deliver(ctx, m); err != nil {
			return err
		}
		// The real signer and orchestrator recorded the certificate; simulate
		// a failure immediately before the worker acknowledges delivery.
		return errors.New("late acknowledgement failure")
	}), orchestrator.DestinationScope{IncludePrefixes: []string{"ca.issue"}})
	if err != nil || !delivered {
		t.Fatalf("late failure: %t %v", delivered, err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+id+"/issuance-result?request_key="+requestKey, token, nil)
	var result struct {
		State    string `json:"state"`
		PEM      string `json:"certificate_pem"`
		Delivery struct {
			Status   string `json:"status"`
			Attempts int    `json:"attempts"`
		} `json:"delivery"`
	}
	if err := json.Unmarshal(body, &result); err != nil || status != http.StatusOK || result.State != "issued" || !strings.HasPrefix(result.PEM, "-----BEGIN CERTIFICATE-----") || result.Delivery.Status != "failed" || result.Delivery.Attempts != 1 {
		t.Fatalf("late failure hid the actual public certificate: %d %s, %v", status, body, err)
	}
}
