// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Q4: an agent gets a 10-minute identity, it shows in the broker history, and
// one call revokes it: the issuing CA's OCSP answers revoked, the CRL lists it
// and the agent key set drops its key, so a relying party refuses its next use.
// The revocation is recorded exactly once, naming who revoked it, and the graph
// shows person → agent → credential → resource until the revocation ends it.
func TestServedAgentIdentityOneCallRevokeQ4(t *testing.T) {
	h, _, body := servedPublicBrokerRevocationFixture(t)
	if _, err := h.srv.orch.UpsertTenantMember(t.Context(), h.tenant, store.TenantMember{
		Subject: "alice@ops.example", DisplayName: "Alice Ops", Roles: []string{"operator"}, Source: "test",
	}); err != nil {
		t.Fatal(err)
	}
	alice := seedScopedTokenSubject(t, h.store, h.tenant, "alice@ops.example", "certs:issue", "certs:read", "identities:write", "graph:read")
	reader := seedScopedTokenSubject(t, h.store, h.tenant, "cert-reader", "certs:read", "graph:read")
	body["ttl_seconds"] = 600
	issued := servedBrokerIssue(t, h, alice, "q4-issue", body, http.StatusCreated)

	// A 10-minute identity, visible in the broker history.
	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/broker/agent-identities/"+issued.CertificateID, reader, nil)
	var history struct {
		CertificateID string    `json:"certificate_id"`
		State         string    `json:"state"`
		NotBefore     time.Time `json:"not_before"`
		NotAfter      time.Time `json:"not_after"`
		Issuance      *struct {
			AgentID     string `json:"agent_id"`
			RequestedBy string `json:"requested_by"`
		} `json:"issuance"`
	}
	if err := json.Unmarshal(raw, &history); status != http.StatusOK || err != nil || history.State != "valid" || history.Issuance == nil ||
		history.Issuance.AgentID != "agent-7" {
		t.Fatalf("broker history: HTTP %d %s", status, raw)
	}
	// The CA backdates not-before for clock skew; the identity ends ten
	// minutes after it was issued.
	if left := time.Until(history.NotAfter); left < 9*time.Minute || left > 10*time.Minute+30*time.Second {
		t.Fatalf("identity expires in %s, want about 10 minutes", left)
	}
	cert, err := h.store.GetCertificate(t.Context(), h.tenant, issued.CertificateID)
	if err != nil {
		t.Fatal(err)
	}
	if cert.BrokerIssuance == nil || cert.BrokerIssuance.RequestedBy != "alice@ops.example" {
		t.Fatalf("the broker issuance does not record who asked for it: %+v", cert.BrokerIssuance)
	}
	assertPublicCertificateOCSP(t, h, cert.Serial, "good")
	if keys := q4AgentKeys(t, h, "agent-7"); keys != 1 {
		t.Fatalf("agent key set has %d keys before revocation, want 1", keys)
	}

	// The graph shows person → agent → credential → resource.
	pathQuery := "/api/v1/graph/path?" + url.Values{"from": {"person:alice@ops.example"}, "to": {"res:agent-scope:tool:inventory"}}.Encode()
	status, raw = secretsReq(t, h, http.MethodGet, pathQuery, reader, nil)
	var path struct {
		Path struct {
			Nodes []struct {
				ID   string `json:"id"`
				Kind string `json:"kind"`
			} `json:"nodes"`
			Edges []struct {
				Type       string `json:"type"`
				Source     string `json:"source"`
				Confidence string `json:"confidence"`
			} `json:"edges"`
		} `json:"path"`
	}
	if err := json.Unmarshal(raw, &path); status != http.StatusOK || err != nil || len(path.Path.Nodes) != 4 {
		t.Fatalf("person → agent → credential → resource: HTTP %d %s", status, raw)
	}
	wantKinds := []string{"person", "ai-agent", "credential", "resource"}
	wantEdges := []string{"DELEGATED", "HOLDS", "GRANTS_ACCESS"}
	for i, node := range path.Path.Nodes {
		if node.Kind != wantKinds[i] {
			t.Fatalf("path node %d = %+v, want kind %s (%s)", i, node, wantKinds[i], raw)
		}
	}
	for i, edge := range path.Path.Edges {
		if edge.Type != wantEdges[i] || edge.Confidence != "authoritative" {
			t.Fatalf("path edge %d = %+v, want %s (%s)", i, edge, wantEdges[i], raw)
		}
	}
	if path.Path.Nodes[1].ID != "aiagent:agent-7" || path.Path.Nodes[2].ID != "cert:"+issued.CertificateID {
		t.Fatalf("path = %s", raw)
	}

	// One call revokes it. Only a broker identity is revocable here, and only
	// with certificate issuance authority.
	route := "/api/v1/broker/agent-identities/" + issued.CertificateID + "/revoke"
	request := map[string]any{"reason": "keyCompromise"}
	if status, _ := secretsReqKey(t, h, http.MethodPost, route, reader, "q4-reader", request); status != http.StatusForbidden {
		t.Fatalf("a read-only principal revoked an agent identity: HTTP %d", status)
	}
	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/broker/agent-identities/00000000-0000-4000-8000-000000000000/revoke",
		alice, "q4-missing", request); status != http.StatusNotFound {
		t.Fatalf("revoking a certificate that is not a broker identity: HTTP %d, want 404", status)
	}
	if status, _ := secretsReqKey(t, h, http.MethodPost, route, alice, "q4-no-reason", map[string]any{}); status != http.StatusBadRequest {
		t.Fatalf("revoking without a reason: HTTP %d, want 400", status)
	}
	status, raw = secretsReqKey(t, h, http.MethodPost, route, alice, "q4-revoke", request)
	var result orchestrator.BulkRevokeResult
	if status != http.StatusOK || json.Unmarshal(raw, &result) != nil || result.TotalRevoked != 1 || result.TotalFailed != 0 {
		t.Fatalf("one-call revoke: HTTP %d %s", status, raw)
	}
	if status, replay := secretsReqKey(t, h, http.MethodPost, route, alice, "q4-revoke", request); status != http.StatusOK || string(replay) != string(raw) {
		t.Fatalf("an exact retry did not replay the original result: HTTP %d %s", status, replay)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}

	// Relying parties refuse the next use: OCSP, the CRL and the key set agree.
	assertPublicCertificateOCSP(t, h, cert.Serial, "revoked")
	status, crlDER := secretsReq(t, h, http.MethodGet, "/crl/"+h.tenant+".crl", "", nil)
	if status != http.StatusOK {
		t.Fatalf("public CRL: HTTP %d", status)
	}
	crl, err := crypto.ParseCRL(crlDER, h.srv.agentBroker.caCertDER)
	if err != nil || !containsSerial(crl.RevokedSerials, cert.Serial) {
		t.Fatalf("the signed CRL does not list the revoked agent identity: %v", err)
	}
	if keys := q4AgentKeys(t, h, "agent-7"); keys != 0 {
		t.Fatalf("the revoked agent's key is still published (%d keys)", keys)
	}
	status, raw = secretsReq(t, h, http.MethodGet, "/api/v1/broker/agent-identities/"+issued.CertificateID, reader, nil)
	if err := json.Unmarshal(raw, &history); status != http.StatusOK || err != nil || history.State != "revoked" {
		t.Fatalf("broker history after revoke: HTTP %d %s", status, raw)
	}

	// Recorded exactly once, naming who revoked it.
	var revocations []events.Event
	if err := h.log.Replay(t.Context(), 1, func(ev events.Event) error {
		if ev.Type == projections.EventCertificateRevocationBatchApplied && ev.TenantID == h.tenant && strings.Contains(string(ev.Data), issued.CertificateID) {
			revocations = append(revocations, ev)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(revocations) != 1 || revocations[0].Actor == nil || revocations[0].Actor.Subject != "alice@ops.example" {
		t.Fatalf("revocation events = %d (actor %+v), want exactly one naming alice@ops.example", len(revocations), q4Actor(revocations))
	}

	// The revoked credential no longer grants access.
	if status, _ := secretsReq(t, h, http.MethodGet, pathQuery, reader, nil); status != http.StatusNotFound {
		t.Fatalf("the graph still routes through the revoked credential: HTTP %d", status)
	}
}

func q4AgentKeys(t *testing.T, h *servedHarness, agent string) int {
	t.Helper()
	status, raw := secretsReq(t, h, http.MethodGet, "/agent-keys/"+h.tenant+"/"+url.PathEscape(agent)+"/jwks.json", "", nil)
	if status != http.StatusOK {
		t.Fatalf("agent key set: HTTP %d %s", status, raw)
	}
	var set crypto.JWKS
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	return len(set.Keys)
}

func q4Actor(evs []events.Event) any {
	if len(evs) == 0 {
		return nil
	}
	return evs[0].Actor
}
