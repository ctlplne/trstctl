// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/graph"
)

// TestServedAIAgentBrokerIssuesPolicyGatedCredentialIntoGraph is the NHI-03
// acceptance proof. It drives the assembled HTTP API: an AI/MCP agent presents a
// valid proof, policy allows the requested scopes, the served signer-backed CA
// mints a short-lived credential, and the credential appears in the tenant's
// event-sourced credential graph as owned by the agent workload.
func TestServedAIAgentBrokerIssuesPolicyGatedCredentialIntoGraph(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AgentBroker = AgentBrokerConfig{
			Enabled:      true,
			TrustDomain:  "served.test",
			DefaultTTL:   10 * time.Minute,
			MaxTTL:       time.Hour,
			PolicyModule: servedBrokerAllowPolicy,
			Attestors:    []attest.Attestor{servedBrokerAttestor{}},
		}
	})
	token := seedScopedToken(t, h.store, h.tenant, "certs:issue", "certs:read", "graph:read")
	publicKeyPEM := servedAttestedPublicKeyPEM(t)

	issued := servedBrokerIssue(t, h, token, "nhi-03-broker-agent-7", map[string]any{
		"agent_id":       "agent-7",
		"method":         "stub_broker",
		"payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")),
		"public_key_pem": publicKeyPEM,
		"scopes":         []string{"mcp:graph.read", "tool:inventory.read"},
	}, http.StatusCreated)
	if issued.AgentID != "agent-7" || issued.Subject != "agent-7" || issued.CredentialID == "" {
		t.Fatalf("broker response = %+v", issued)
	}
	if issued.NotAfter.IsZero() || !containsString(issued.Scopes, "mcp:graph.read") {
		t.Fatalf("broker response missing expiry/scope: %+v", issued)
	}

	replay := servedBrokerIssue(t, h, token, "nhi-03-broker-agent-7", map[string]any{
		"agent_id":       "agent-7",
		"method":         "stub_broker",
		"payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")),
		"public_key_pem": publicKeyPEM,
		"scopes":         []string{"mcp:graph.read", "tool:inventory.read"},
	}, http.StatusCreated)
	if replay.CertificatePEM != issued.CertificatePEM || replay.CredentialID != issued.CredentialID {
		t.Fatalf("idempotent replay changed broker credential: first=%+v replay=%+v", issued, replay)
	}

	denied := servedBrokerIssue(t, h, token, "nhi-03-broker-denied", map[string]any{
		"agent_id":       "agent-denied",
		"method":         "stub_broker",
		"payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")),
		"public_key_pem": publicKeyPEM,
		"scopes":         []string{"admin:*"},
	}, http.StatusForbidden)
	if denied.CredentialID != "" {
		t.Fatalf("policy-denied broker request returned a credential: %+v", denied)
	}

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/graph", token, nil)
	if status != http.StatusOK {
		t.Fatalf("get graph = %d, want 200; body=%s", status, body)
	}
	var snap struct {
		Nodes []graph.Node `json:"nodes"`
		Edges []graph.Edge `json:"edges"`
	}
	if err := json.Unmarshal(body, &snap); err != nil {
		t.Fatalf("decode graph: %v; body=%s", err, body)
	}
	agentNode, credentialNode := "", ""
	for _, n := range snap.Nodes {
		if n.Kind == graph.KindWorkload && n.Name == "agent-7" && n.Attrs["owner_kind"] == "workload" {
			agentNode = n.ID
		}
		if n.Kind == graph.KindCredential && n.ID == "cert:"+issued.CertificateID {
			credentialNode = n.ID
		}
	}
	if agentNode == "" || credentialNode == "" {
		t.Fatalf("graph missing broker agent/credential nodes: agent=%q credential=%q nodes=%+v", agentNode, credentialNode, snap.Nodes)
	}
	if !hasGraphEdge(snap.Edges, agentNode, credentialNode, graph.EdgeOwns) {
		t.Fatalf("graph missing broker ownership edge %s --OWNS--> %s; edges=%+v", agentNode, credentialNode, snap.Edges)
	}

	for _, eventType := range []string{"attestation.verified", "attestation.bound", "ephemeral.issued", "agent.identity.issued", "agent.identity.refused", "certificate.recorded"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("served broker did not emit %s", eventType)
		}
	}
}

const servedBrokerAllowPolicy = `package trstctl.policy

default allow := false
default reason := "scope not permitted"

allow if {
	input.action == "issue"
	input.attrs.agent_id == "agent-7"
	every scope in input.attrs.scopes {
		scope != "admin:*"
	}
}
`

type servedBrokerAttestor struct{}

func (servedBrokerAttestor) Method() string { return "stub_broker" }

func (servedBrokerAttestor) Attest(_ context.Context, p []byte) (attest.Attestation, error) {
	if string(p) != "genuine" {
		return attest.Attestation{}, errServedBrokerForgery
	}
	return attest.Attestation{
		Method:    "stub_broker",
		Subject:   "agent-7",
		Selectors: []string{"broker:test"},
	}, nil
}

var errServedBrokerForgery = errors.New("forged broker proof")

type servedBrokerIssueResponse struct {
	AgentID        string    `json:"agent_id"`
	NodeID         string    `json:"node_id"`
	Subject        string    `json:"subject"`
	CredentialID   string    `json:"credential_id"`
	CertificateID  string    `json:"certificate_id"`
	CertificatePEM string    `json:"certificate_pem"`
	SPIFFEID       string    `json:"spiffe_id"`
	Scopes         []string  `json:"scopes"`
	NotAfter       time.Time `json:"not_after"`
}

func servedBrokerIssue(t *testing.T, h *servedHarness, token, idemKey string, req map[string]any, want int) servedBrokerIssueResponse {
	t.Helper()
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/broker/agent-identities", token, idemKey, req)
	if status != want {
		t.Fatalf("broker issue status = %d, want %d; body=%s", status, want, body)
	}
	var out servedBrokerIssueResponse
	if status == http.StatusCreated {
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("decode broker response: %v; body=%s", err, body)
		}
	}
	return out
}

func hasGraphEdge(edges []graph.Edge, from, to string, typ graph.EdgeType) bool {
	for _, e := range edges {
		if e.From == from && e.To == to && e.Type == typ {
			return true
		}
	}
	return false
}

func containsString(vals []string, want string) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}
