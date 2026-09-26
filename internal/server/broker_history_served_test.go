// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

type servedBrokerHistoryItem struct {
	CertificateID string                `json:"certificate_id"`
	SPIFFEID      string                `json:"spiffe_id"`
	State         string                `json:"state"`
	StateReason   string                `json:"state_reason"`
	MetadataState string                `json:"metadata_state"`
	NotAfter      *time.Time            `json:"not_after"`
	Issuance      *store.BrokerIssuance `json:"issuance"`
}

type servedBrokerHistoryPage struct {
	Items       []servedBrokerHistoryItem `json:"items"`
	NextCursor  string                    `json:"next_cursor"`
	GeneratedAt time.Time                 `json:"generated_at"`
}

func TestServedBrokerHistoryIsDurableBoundedTenantScopedAndReadOnly(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AgentBroker = AgentBrokerConfig{Enabled: true, TrustDomain: "served.test", PolicyModule: servedBrokerAllowPolicy,
			Attestors: []attest.Attestor{servedBrokerAttestor{}}}
	})
	issuer := seedScopedToken(t, h.store, h.tenant, "certs:issue")
	reader := seedScopedToken(t, h.store, h.tenant, "certs:read")
	const neighborTenant = "22222222-2222-2222-2222-222222222222"
	registerServedTenantID(t, h, neighborTenant, "Broker history neighbor")
	neighbor := seedScopedToken(t, h.store, neighborTenant, "certs:read")
	signer := &countingEphemeralDigestSigner{DigestSigner: h.srv.agentBroker.caSigner}
	h.srv.agentBroker.caSigner = signer
	body := map[string]any{"agent_id": "agent-7", "method": "stub_broker", "payload_base64": "Z2VudWluZQ==",
		"public_key_pem": servedAttestedPublicKeyPEM(t), "scopes": []string{"tool:inventory.read"}, "ttl_seconds": 120}
	first := servedBrokerIssue(t, h, issuer, "broker-history-first", body, http.StatusCreated)
	second := servedBrokerIssue(t, h, issuer, "broker-history-second", body, http.StatusCreated)
	read := func(path, token string, want int) []byte {
		t.Helper()
		status, raw := secretsReq(t, h, http.MethodGet, path, token, nil)
		if status != want {
			t.Fatalf("history GET %s status=%d want=%d body=%s", path, status, want, raw)
		}
		return raw
	}
	head, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	before := ephemeralPreviewMutationState(t, h)
	var page servedBrokerHistoryPage
	if err := json.Unmarshal(read("/api/v1/broker/agent-identities?limit=1", reader, http.StatusOK), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.NextCursor == "" || page.GeneratedAt.IsZero() {
		t.Fatalf("history is not bounded and timestamped: %+v", page)
	}
	one := page.Items[0]
	wantID := "spiffe://served.test/_trstctl/v1/tenant/" + h.tenant + "/broker/agent/agent-7/method/stub_broker/subject/agent-7"
	assertSignedWorkloadIDHandoff(t, first.CertificatePEM, first.SPIFFEID, wantID)
	if one.SPIFFEID != wantID {
		t.Fatal("history list omitted the exact signed workload ID")
	}
	if one.State != "valid" || one.StateReason == "" || one.MetadataState != "recorded" || one.Issuance == nil || one.Issuance.AgentID != "agent-7" || len(one.Issuance.Scopes) != 1 || one.Issuance.Scopes[0] != "tool:inventory.read" {
		t.Fatalf("history lost original issuance or validity meaning: %+v", one)
	}
	if err := json.Unmarshal(read("/api/v1/broker/agent-identities?limit=1&cursor="+url.QueryEscape(page.NextCursor), reader, http.StatusOK), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.NextCursor != "" || page.Items[0].CertificateID == one.CertificateID {
		t.Fatal("keyset pagination duplicated an item or invented another page")
	}
	wanted := map[string]bool{first.CertificateID: true, second.CertificateID: true}
	if !wanted[one.CertificateID] || !wanted[page.Items[0].CertificateID] {
		t.Fatal("history returned a certificate outside the broker issuance set")
	}
	var detail servedBrokerHistoryItem
	raw := read("/api/v1/broker/agent-identities/"+first.CertificateID, reader, http.StatusOK)
	if err := json.Unmarshal(raw, &detail); err != nil || detail.CertificateID != first.CertificateID || detail.Issuance == nil {
		t.Fatalf("detail lost durable identity: %v", err)
	}
	if detail.SPIFFEID != wantID {
		t.Fatal("history detail omitted or reconstructed the signed workload ID")
	}
	for _, forbidden := range []string{"certificate_pem", "certificate_der", "issuance_request_binding", "issuance_idempotency_key", "broker-history-first", "payload_base64", "task_envelope_base64"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("history exposed non-history field %s", forbidden)
		}
	}
	if err := json.Unmarshal(read("/api/v1/broker/agent-identities", neighbor, http.StatusOK), &page); err != nil || len(page.Items) != 0 {
		t.Fatal("neighbor could list broker certificates")
	}
	read("/api/v1/broker/agent-identities/"+first.CertificateID, neighbor, http.StatusNotFound)
	for _, query := range []string{"limit=0", "limit=101", "cursor=bad", "state=imaginary", "method=" + strings.Repeat("x", 129), "q=" + strings.Repeat("x", 201)} {
		read("/api/v1/broker/agent-identities?"+query, reader, http.StatusBadRequest)
	}
	if after, err := h.log.LastSequence(t.Context()); err != nil || after != head || ephemeralPreviewMutationState(t, h) != before || signer.calls.Load() != 2 {
		t.Fatal("history reads wrote state or signed")
	}
	// Successful, invalid and tenant-isolated reads above have zero effects.
	// A permission refusal records exactly one denial, without a broker effect.
	read("/api/v1/broker/agent-identities", issuer, http.StatusForbidden)
	read("/api/v1/broker/agent-identities", "", http.StatusUnauthorized)
	assertBrokerDenialAuditOnly(t, h, head, "certs:read", "GET /api/v1/broker/agent-identities")
	if ephemeralPreviewMutationState(t, h) != before || signer.calls.Load() != 2 {
		t.Fatal("denial changed broker state or signed")
	}
	cert, err := h.store.GetCertificate(t.Context(), h.tenant, first.CertificateID)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.agentBroker.orch.RevokeCertificate(t.Context(), h.tenant, cert.Fingerprint, cert.Serial, "test compromise", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(read("/api/v1/broker/agent-identities?state=revoked&method=stub_broker&q=agent-7", reader, http.StatusOK), &page); err != nil || len(page.Items) != 1 || page.Items[0].CertificateID != first.CertificateID || page.Items[0].State != "revoked" || page.Items[0].SPIFFEID != wantID {
		t.Fatalf("filtered history did not read the shared revocation state: %v", err)
	}
	// History belongs to the inventory, not the optional signing service.
	h.srv.agentBroker = nil
	read("/api/v1/broker/agent-identities", reader, http.StatusOK)
	read("/api/v1/broker/agent-identities/"+first.CertificateID, reader, http.StatusOK)
}

func assertBrokerDenialAuditOnly(t *testing.T, h *servedHarness, head uint64, permission, target string) {
	t.Helper()
	var appended []events.Event
	if err := h.log.Replay(t.Context(), head+1, func(ev events.Event) error { appended = append(appended, ev); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(appended) != 1 {
		t.Fatalf("denied request appended %d events, want exactly one attributable denial", len(appended))
	}
	event := appended[0]
	var decision orchestrator.AuthzDecision
	if err := json.Unmarshal(event.Data, &decision); err != nil {
		t.Fatal(err)
	}
	if event.Type != orchestrator.EventAuthzDecision || event.TenantID != h.tenant || event.Actor.Subject != "secrets-test" || decision.Actor != "secrets-test" || decision.Permission != permission || decision.Target != target || decision.Resource != "api_route" || decision.Decision != "deny" {
		t.Fatalf("unexpected effect for denied broker request: event=%+v decision=%+v", event, decision)
	}
}
