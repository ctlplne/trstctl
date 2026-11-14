// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	agidapi "trstctl.com/trstctl/internal/agentid/api"
	"trstctl.com/trstctl/internal/agentid/delegation"
	"trstctl.com/trstctl/internal/agentid/delegation/brokerstore"
	agidstore "trstctl.com/trstctl/internal/agentid/delegation/store"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// Q4-L4 Done-when: an AGID chain-bound credential is in the access graph with
// the delegation chain it was issued under. Alice (a tenant member) delegated
// to a planner agent for fs.read, fs.write and the orders database, the
// planner narrowed it to fs.read and orders for read and delegated to a worker
// agent, and the production recorder registered a chain-bound credential for
// the worker, with a second one that a revocation directive then covers. Who
// can reach the fs tool for read lists the live credential, held by the
// worker, with the chain back to Alice; the revoked one grants nothing; the
// path from Alice to the database runs through both delegations; all through
// the AGID family's own API attach.
func TestServedChainBoundCredentialsAndTheirDelegationChainsQ4L4(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.Store.WithExtraMigrations(agidstore.MigrationsFS())
		if err := d.Store.Migrate(t.Context()); err != nil {
			t.Fatalf("AGID migrations: %v", err)
		}
		d.LicensedAPIOptionsFactory = agidapi.NewAPIOptionsFactory()
	})
	registerServedTenant(t, h, "Chain-bound credentials in the access graph")
	if _, err := h.srv.orch.UpsertTenantMember(t.Context(), h.tenant, store.TenantMember{
		Subject: "q4l4-alice@ops.example", DisplayName: "Alice Delegator", Roles: []string{"operator"}, Source: "test",
	}); err != nil {
		t.Fatal(err)
	}
	viewer := seedScopedTokenSubject(t, h.store, h.tenant, "q4l4-viewer", "graph:read", "access:read")

	now := time.Now().UTC()
	window := delegation.Window{NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(time.Hour).Unix()}
	hops := []struct {
		delegator, delegate string
		remaining           uint32
		authority           delegation.Authority
	}{
		{"q4l4-alice@ops.example", "q4l4-planner", 1, delegation.Authority{Tools: []string{"fs.read", "fs.write"}, Scopes: []string{"read", "write"},
			Resources: []delegation.ResourceSelector{{Kind: "db", Value: "orders"}}, Depth: 2, Validity: window}},
		{"q4l4-planner", "q4l4-worker", 0, delegation.Authority{Tools: []string{"fs.read"}, Scopes: []string{"read"},
			Resources: []delegation.ResourceSelector{{Kind: "db", Value: "orders"}}, Depth: 1, Validity: window}},
	}
	signers := make([]crypto.Signer, len(hops))
	for i := range hops {
		s, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		signers[i] = s
	}
	var chain []delegation.RecordEnvelope
	var parent []byte
	for i, hop := range hops {
		rec := delegation.Record{
			TenantID: h.tenant, DelegatorID: hop.delegator, DelegateID: hop.delegate,
			DelegatorKey: delegation.KeyRef{ID: hop.delegator + "-key", Algorithm: "ECDSA-P256"},
			Authority:    hop.authority, DepthRemaining: hop.remaining, Validity: window,
		}
		if i+1 < len(hops) {
			rec.DelegateKeyThumbprint = delegation.DelegateKeyThumbprintOf(signers[i+1].Public().DER)
		}
		if i == 0 {
			rec.RootAnchor = true
		} else {
			rec.ParentDigest = parent
		}
		signed, err := rec.Sign(signers[i], nil)
		if err != nil {
			t.Fatal(err)
		}
		if parent, err = signed.Digest(nil); err != nil {
			t.Fatal(err)
		}
		chain = append(chain, delegation.RecordEnvelope{Record: signed, DelegatorPublicDER: signers[i].Public().DER})
	}
	recorder := brokerstore.New(h.store)
	for _, credential := range []string{"q4l4-live", "q4l4-revoked"} {
		if err := recorder.RecordIssuanceBinding(t.Context(), delegation.IssuanceBinding{
			TenantID: h.tenant, IdempotencyKey: credential + "-issue", CredentialID: credential, SubjectID: "q4l4-worker",
			ChainHeadDigest: parent, ChainDigest: parent, AgentStackDigest: []byte("q4l4-stack"),
			NotBefore: window.NotBefore, NotAfter: window.NotAfter, Chain: chain,
		}); err != nil {
			t.Fatalf("record the %s issuance: %v", credential, err)
		}
	}
	if err := agidstore.New(h.store).InsertRevocationDirectiveWithJobs(t.Context(), h.tenant,
		agidstore.RevocationDirective{DirectiveID: "q4l4-directive", SubjectID: "q4l4-worker", Reason: "test", Watermark: 1},
		[]agidstore.RevocationJob{{DirectiveID: "q4l4-directive", IdempotencyKey: "q4l4-revoked-job", CredentialID: "q4l4-revoked"}}); err != nil {
		t.Fatal(err)
	}

	type link struct {
		Node struct {
			ID string `json:"id"`
		} `json:"node"`
		Edge struct {
			From   string `json:"from"`
			To     string `json:"to"`
			Type   string `json:"type"`
			Source string `json:"source"`
		} `json:"edge"`
	}
	var answer struct {
		Access []struct {
			Credential struct {
				ID    string            `json:"id"`
				Attrs map[string]string `json:"attrs"`
			} `json:"credential"`
			Grant struct {
				Actions []string `json:"actions"`
			} `json:"grant"`
			Holders     []link `json:"holders"`
			Delegations []link `json:"delegations"`
		} `json:"access"`
	}
	query := "/api/v1/graph/reachers/" + url.PathEscape("res:agent-scope:tool:fs") + "?action=read"
	status, raw := secretsReq(t, h, http.MethodGet, query, viewer, nil)
	if status != http.StatusOK || json.Unmarshal(raw, &answer) != nil || len(answer.Access) != 1 {
		t.Fatalf("who can reach the fs tool for read: HTTP %d %s", status, raw)
	}
	grant := answer.Access[0]
	if grant.Credential.ID != "agid:q4l4-live" || grant.Credential.Attrs["subject"] != "q4l4-worker" || strings.Join(grant.Grant.Actions, ",") != "read" {
		t.Fatalf("the chain-bound grant = %+v", grant)
	}
	if len(grant.Holders) != 1 || grant.Holders[0].Node.ID != "principal:q4l4-worker" || grant.Holders[0].Edge.Source != "agent chain-bound issuance" {
		t.Fatalf("holders = %+v", grant.Holders)
	}
	var delegations []string
	for _, d := range grant.Delegations {
		if d.Edge.Type != "DELEGATED" || d.Edge.Source != "agent delegation record" {
			t.Fatalf("delegation link = %+v", d)
		}
		delegations = append(delegations, d.Edge.From+">"+d.Edge.To)
	}
	if got := strings.Join(delegations, " "); got != "principal:q4l4-planner>principal:q4l4-worker person:q4l4-alice@ops.example>principal:q4l4-planner" {
		t.Fatalf("the delegation chain = %s", got)
	}

	// The revoked credential is held but grants nothing.
	status, raw = secretsReq(t, h, http.MethodGet, "/api/v1/graph", viewer, nil)
	var whole struct {
		Nodes []struct {
			ID    string            `json:"id"`
			Attrs map[string]string `json:"attrs"`
		} `json:"nodes"`
		Edges []struct {
			From string `json:"from"`
			Type string `json:"type"`
		} `json:"edges"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &whole) != nil {
		t.Fatalf("graph: HTTP %d %s", status, raw)
	}
	revokedShown := false
	for _, n := range whole.Nodes {
		if n.ID == "agid:q4l4-revoked" && n.Attrs["revoked"] == "true" {
			revokedShown = true
		}
	}
	for _, e := range whole.Edges {
		if e.From == "agid:q4l4-revoked" && e.Type == "GRANTS_ACCESS" {
			t.Fatalf("the revoked chain-bound credential grants access: %+v", e)
		}
	}
	if !revokedShown {
		t.Fatalf("the revoked chain-bound credential is not shown: %s", raw)
	}

	pathQuery := "/api/v1/graph/path?" + url.Values{"from": {"person:q4l4-alice@ops.example"}, "to": {"res:agent-resource:db:orders"}}.Encode()
	status, raw = secretsReq(t, h, http.MethodGet, pathQuery, viewer, nil)
	var path struct {
		Path struct {
			Edges []struct {
				Type    string   `json:"type"`
				Actions []string `json:"actions"`
			} `json:"edges"`
		} `json:"path"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &path) != nil || len(path.Path.Edges) != 4 ||
		path.Path.Edges[0].Type != "DELEGATED" || path.Path.Edges[1].Type != "DELEGATED" || path.Path.Edges[2].Type != "HOLDS" ||
		path.Path.Edges[3].Type != "GRANTS_ACCESS" || strings.Join(path.Path.Edges[3].Actions, ",") != "read" {
		t.Fatalf("Alice → planner → worker → credential → orders: HTTP %d %s", status, raw)
	}
	t.Logf("Q4L4_OK credential=agid:q4l4-live chain=%d", len(chain))
}
