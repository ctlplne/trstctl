// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Owner decision 2026-10-24 (A120/A130/A132): a per-tenant switch over
// control-plane key generation instead of removing the generators. A tenant
// that predates the switch reads undecided and keeps what it had; an operator
// with access:write turns it off or on with a reason; every change is a
// tenant.control_plane_keygen.set event and survives a full rebuild.
func TestServedTenantSwitchesControlPlaneKeygenWithAReason(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "alice@customer.test", "access:read", "access:write")
	reader := seedScopedTokenSubject(t, h.store, h.tenant, "reader@customer.test", "access:read")
	type decision struct {
		Decided                bool     `json:"decided"`
		Enabled                bool     `json:"enabled"`
		Source                 string   `json:"source"`
		Reason                 string   `json:"reason"`
		SetBy                  string   `json:"set_by"`
		ControlPlaneIdentities int64    `json:"control_plane_identities"`
		Paths                  []string `json:"paths"`
	}
	read := func(token string) decision {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/tenant/key-generation", token, nil)
		var out decision
		if status != http.StatusOK || json.Unmarshal(body, &out) != nil {
			t.Fatalf("read key generation = %d %s", status, body)
		}
		return out
	}
	if got := read(reader); got.Decided || !got.Enabled || len(got.Paths) != 4 {
		t.Fatalf("pre-switch tenant = %+v, want undecided, still allowed, the governed paths named", got)
	}
	if status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/tenant/key-generation", reader, "cpk-reader", map[string]any{"enabled": false, "reason": "x"}); status != http.StatusForbidden {
		t.Fatalf("change with access:read = %d %s, want 403", status, body)
	}
	if status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/tenant/key-generation", admin, "cpk-no-reason", map[string]any{"enabled": false}); status != http.StatusBadRequest || !strings.Contains(string(body), "reason") {
		t.Fatalf("change without a reason = %d %s, want 400 naming the reason", status, body)
	}
	if status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/tenant/key-generation", admin, "cpk-no-enabled", map[string]any{"reason": "x"}); status != http.StatusBadRequest {
		t.Fatalf("change without enabled = %d %s, want 400", status, body)
	}
	status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/tenant/key-generation", admin, "cpk-off", map[string]any{"enabled": false, "reason": "every workload brings a CSR now"})
	if status != http.StatusOK || !strings.Contains(string(body), `"enabled":false`) || !strings.Contains(string(body), `"source":"operator"`) || !strings.Contains(string(body), "alice@customer.test") {
		t.Fatalf("turn off = %d %s", status, body)
	}
	if !h.hasEvent(t, "tenant.control_plane_keygen.set") {
		t.Fatal("the change left no tenant.control_plane_keygen.set event")
	}
	if got := read(reader); !got.Decided || got.Enabled || got.Source != "operator" || got.Reason != "every workload brings a CSR now" {
		t.Fatalf("after turning off = %+v", got)
	}
	if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("full projection rebuild: %v", err)
	}
	if got := read(reader); !got.Decided || got.Enabled || got.SetBy != "alice@customer.test" {
		t.Fatalf("after a full rebuild = %+v, want the operator's decision", got)
	}
	if status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/tenant/key-generation", admin, "cpk-on", map[string]any{"enabled": true, "reason": "a legacy batch job still needs it this week"}); status != http.StatusOK || !strings.Contains(string(body), `"enabled":true`) {
		t.Fatalf("turn back on = %d %s", status, body)
	}
}

// With the switch off, an identity issuance that would generate the subject
// key in the control plane is refused before anything is recorded, and the
// refusal names every replacement. A CSR still issues, and turning the switch
// back on restores the old path.
func TestServedKeygenOffRefusesIssuanceWithoutACSRBeforeRecording(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	tok := seedScopedTokenSubject(t, h.store, h.tenant, "alice@customer.test", "owners:read", "owners:write", "identities:read",
		"identities:write", "certs:read", "certs:issue", "access:read", "access:write")
	if status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/tenant/key-generation", tok, "cpk-off",
		map[string]any{"enabled": false, "reason": "requesters bring their own keys"}); status != http.StatusOK {
		t.Fatalf("turn off = %d %s", status, body)
	}
	owner, err := h.store.CreateOwner(ctx, store.Owner{TenantID: h.tenant, Kind: store.OwnerWorkload, Name: "keygen-off"})
	if err != nil {
		t.Fatal(err)
	}
	identityNamed := func(name string) string {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{"owner_id": owner.ID, "kind": "x509", "name": name})
		var ident struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &ident) != nil {
			t.Fatalf("create identity %s = %d: %s", name, status, body)
		}
		return ident.ID
	}
	id := identityNamed("keygen-off.example.test")
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+id+"/transitions/preview", tok, map[string]any{"to": "issued", "reason": "no csr"})
	var preview struct {
		Ready         bool     `json:"ready"`
		KeygenRefused bool     `json:"keygen_refused"`
		Warnings      []string `json:"warnings"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &preview) != nil || preview.Ready || !preview.KeygenRefused ||
		!strings.Contains(strings.Join(preview.Warnings, " "), "subject_csr_pem") {
		t.Fatalf("preview of an issue without a CSR while off = %d %s, want not ready with the switch named", status, body)
	}
	before, err := h.log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+id+"/transitions", tok, "issue-without-csr", map[string]any{"to": "issued", "reason": "no csr"})
	if status != http.StatusConflict || !strings.Contains(string(body), "control_plane_keygen_off") ||
		!strings.Contains(string(body), "subject_csr_pem") || !strings.Contains(string(body), "agent-executed target") {
		t.Fatalf("issue without a CSR while off = %d %s, want 409 naming every replacement", status, body)
	}
	if after, err := h.log.LastSequence(ctx); err != nil || after != before {
		t.Fatalf("the refused issue recorded events: %d -> %d (%v)", before, after, err)
	}
	if got, err := h.store.GetIdentity(ctx, h.tenant, id); err != nil || got.Status != "requested" {
		t.Fatalf("the refused issue moved the identity: %s %v", got.Status, err)
	}
	// A requester's CSR issues as before.
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: badSubjectCSR(t, key,
		crypto.CertificateRequestTemplate{CommonName: "keygen-off.example.test", DNSNames: []string{"keygen-off.example.test"}})})
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+id+"/transitions", tok, "issue-with-csr",
		map[string]any{"to": "issued", "reason": "requester key", "subject_csr_pem": string(csr)})
	if status != http.StatusOK {
		t.Fatalf("issue with a CSR while off = %d %s", status, body)
	}
	// Turning the switch back on restores issuance without a CSR.
	if status, body := secretsReqKey(t, h, http.MethodPut, "/api/v1/tenant/key-generation", tok, "cpk-on",
		map[string]any{"enabled": true, "reason": "a legacy batch job still needs it"}); status != http.StatusOK {
		t.Fatalf("turn on = %d %s", status, body)
	}
	other := identityNamed("keygen-on.example.test")
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+other+"/transitions", tok, "issue-on",
		map[string]any{"to": "issued", "reason": "no csr, allowed"}); status != http.StatusOK {
		t.Fatalf("issue without a CSR while on = %d %s", status, body)
	}
}

// An identity bound to an agent-executed target has its key generated by the
// host, not the control plane, so the switch does not stand in its way.
func TestServedKeygenOffStillIssuesForAnAgentExecutedTarget(t *testing.T) {
	h, _, identityID := servedHostRevocationFixture(t, func(h *roleHarness) {
		if _, err := h.srv.orch.SetControlPlaneKeygen(t.Context(), h.tenant, projections.ControlPlaneKeygenSet{
			Enabled: false, Source: store.ControlPlaneKeygenSourceOperator, Reason: "host agents generate every key", SetBy: "ops@example.test",
		}); err != nil {
			t.Fatal(err)
		}
	})
	got, err := h.store.GetIdentity(t.Context(), h.tenant, identityID)
	if err != nil || got.Status != "issued" {
		t.Fatalf("host-executed first issuance with the switch off = %s %v, want issued and handed to the host", got.Status, err)
	}
	job := claimOneRenewal(t, t.Context(), h)
	if job.JobID == 0 {
		t.Fatal("no host job for the host-executed identity")
	}
}
