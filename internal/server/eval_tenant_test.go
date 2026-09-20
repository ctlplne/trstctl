// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestServedEvalFirstCertificateRevokesWithBlankTenancy(t *testing.T) {
	cfg := config.Default()
	cfg.Protocols.Profile = config.ProtocolProfileEval
	cfg.Protocols.EvalTenantID = servedTestTenant
	cfg.Protocols.SPIFFE.SocketPath = t.TempDir() + "/workload.sock"
	cfg.Protocols.TSACertFile = t.TempDir() + "/tsa.crt"
	cfg.Protocols.RAKeyFile = t.TempDir() + "/ra.key"
	protocols, err := evalProtocolProfileFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// No fixture registers the tenant. The actual server assembly must do so.
	h := newServedHarness(t, protocols)
	authority, err := orchestrator.ResolveLiveTenantRegistrationAuthority(t.Context(), h.log, h.store, h.tenant)
	if err != nil || authority.EventSequence == 0 {
		t.Fatalf("blank evaluation has no durable tenant: %+v %v", authority, err)
	}
	token := seedScopedToken(t, h.store, h.tenant, "owners:write", "identities:write", "identities:read", "certs:issue", "certs:read")
	owner := servedCreateID(t, h, token, "eval-owner", "/api/v1/owners", map[string]any{"kind": "workload", "name": "payments"})
	id := servedCreateID(t, h, token, "eval-identity", "/api/v1/identities", map[string]any{"kind": "x509_certificate", "name": "payments.example.test", "owner_id": owner})
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+id+"/transitions", token, "eval-first-leaf", map[string]any{"to": "issued", "subject_csr_pem": string(subjectCSR(t, "payments.example.test"))})
	if status != http.StatusOK {
		t.Fatalf("issue = %d %s", status, body)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+id+"/issuance-result?request_key=eval-first-leaf", token, nil)
	var result struct {
		Certificate struct {
			ID string `json:"id"`
		} `json:"certificate"`
	}
	if err := json.Unmarshal(body, &result); err != nil || status != http.StatusOK || result.Certificate.ID == "" {
		t.Fatalf("first leaf = %d %s %v", status, body, err)
	}
	request := map[string]any{"certificate_ids": []string{result.Certificate.ID}, "reason": "cessationOfOperation"}
	for attempt := 0; attempt < 2; attempt++ {
		status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", token, "eval-revoke-first-leaf", request)
		if status != http.StatusOK {
			t.Fatalf("exact revocation attempt %d = %d %s", attempt, status, body)
		}
		cert, err := h.store.GetCertificate(t.Context(), h.tenant, result.Certificate.ID)
		if err != nil || cert.Status != "revoked" {
			t.Fatalf("exact leaf %s status=%s not revoked: response=%s err=%v", cert.ID, cert.Status, body, err)
		}
	}
	if err := projections.New(h.store).Rebuild(t.Context(), h.log); err != nil {
		t.Fatal(err)
	}
	d := Deps{Store: h.store, Log: h.log, Protocols: protocols}
	if err := ensureEvalTenantRegistration(t.Context(), d); err != nil {
		t.Fatal(err)
	}
	again, err := orchestrator.ResolveLiveTenantRegistrationAuthority(t.Context(), h.log, h.store, h.tenant)
	if err != nil || again != authority {
		t.Fatalf("restart/replay changed tenant authority: %+v %v", again, err)
	}
	if _, err := h.store.OffboardTenant(t.Context(), h.tenant); err != nil {
		t.Fatal(err)
	}
	if err := ensureEvalTenantRegistration(t.Context(), d); !errors.Is(err, store.ErrTenantRegistrationConflict) {
		t.Fatalf("eval startup resurrects erased tenant: %v", err)
	}
}

func TestProductionProtocolConfigurationDoesNotCreateTenant(t *testing.T) {
	h := newServedHarness(t, config.Protocols{})
	if _, err := h.store.GetTenant(t.Context(), h.tenant); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("production protocol defaults created a tenant: %v", err)
	}
}
