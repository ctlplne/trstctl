// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

type g1Node struct {
	ID    string            `json:"id"`
	Kind  string            `json:"kind"`
	Name  string            `json:"name"`
	Attrs map[string]string `json:"attrs"`
}

type g1Edge struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Type       string `json:"type"`
	Source     string `json:"source"`
	Confidence string `json:"confidence"`
}

type g1Path struct {
	Target g1Node   `json:"target"`
	Nodes  []g1Node `json:"nodes"`
	Edges  []g1Edge `json:"edges"`
}

type g1Link struct {
	Node g1Node `json:"node"`
	Edge g1Edge `json:"edge"`
}

type g1Grant struct {
	Credential g1Node   `json:"credential"`
	Grant      g1Edge   `json:"grant"`
	Path       g1Path   `json:"path"`
	Holders    []g1Link `json:"holders"`
	Approvers  []g1Link `json:"approvers"`
}

type g1Reachers struct {
	Target   g1Node    `json:"target"`
	Reachers []g1Node  `json:"reachers"`
	Access   []g1Grant `json:"access"`
	Coverage struct {
		Sources    []string `json:"sources"`
		NotCovered []string `json:"not_covered"`
		Note       string   `json:"note"`
	} `json:"coverage"`
}

// G1: "who can reach database X?" names the person, workload or AI agent, the
// credential and who approved it, each link with its record and confidence,
// from a real approved PAM grant on a real PostgreSQL target. The answer is
// byte-identical after a fresh server assembly and after a full projection
// rebuild from the event log.
func TestServedWhoCanReachADatabaseNamesHolderCredentialAndApproversAcrossColdRestartG1(t *testing.T) {
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	seedPAMPostgresTable(t, pgDSN)
	adminDSNRef := pamPostgresAdminFileRef(t, pgDSN)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		wirePAMPostgresProvider(d, adminDSNRef, 10*time.Minute)
		d.PAM = PAMConfig{
			Enabled: true, DefaultTTL: 5 * time.Minute, MaxTTL: 10 * time.Minute,
			ExpiryInterval: time.Hour,
			Attestors:      []attest.Attestor{servedPAMAttestor{}},
			PostgresTargets: []PAMPostgresTarget{{
				TenantID: servedTestTenant, ID: "pg-main", ProviderID: "pam-pg-provider",
				AllowedRoles: []string{"readonly"},
			}},
		}
		d.AgentBroker = AgentBrokerConfig{Enabled: true, TrustDomain: "served.test", PolicyModule: servedBrokerAllowPolicy,
			Attestors: []attest.Attestor{servedBrokerAttestor{}}}
	})
	startServedExternalCADispatcher(t, h)
	for _, m := range []store.TenantMember{
		{Subject: "pam-requester", DisplayName: "Rita Requester", Email: "rita@example.test", Roles: []string{"operator"}, Source: "test"},
		{Subject: "pam-reviewer-one", DisplayName: "Rev One", Email: "rev1@example.test", Roles: []string{"admin"}, Source: "test"},
		{Subject: "pam-reviewer-two", DisplayName: "Rev Two", Email: "rev2@example.test", Roles: []string{"admin"}, Source: "test"},
	} {
		if _, err := h.srv.orch.UpsertTenantMember(t.Context(), h.tenant, m); err != nil {
			t.Fatalf("seed member %s: %v", m.Subject, err)
		}
	}
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "pam-requester", "access:read", "access:write")
	reviewerOne := seedScopedTokenSubject(t, h.store, h.tenant, "pam-reviewer-one", "access:approve")
	reviewerTwo := seedScopedTokenSubject(t, h.store, h.tenant, "pam-reviewer-two", "access:approve")
	agentToken := seedScopedTokenSubject(t, h.store, h.tenant, "agent-7", "access:read", "access:write")
	issuer := seedScopedToken(t, h.store, h.tenant, "certs:issue")
	reader := seedScopedTokenSubject(t, h.store, h.tenant, "graph-reader", "graph:read")
	noGraph := seedScopedTokenSubject(t, h.store, h.tenant, "cert-reader", "certs:read")

	agentIdentity := servedBrokerIssue(t, h, issuer, "g1-agent-identity", map[string]any{
		"agent_id": "agent-7", "method": "stub_broker", "payload_base64": "Z2VudWluZQ==",
		"public_key_pem": servedAttestedPublicKeyPEM(t), "scopes": []string{"tool:inventory.read"}, "ttl_seconds": 300,
	}, http.StatusCreated)
	pamRequest := func() map[string]any {
		return map[string]any{
			"target_type": "postgres", "target_id": "pg-main", "role": "readonly",
			"reason": "G1 who-can-reach proof", "method": "stub_pam",
			"payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")), "ttl_seconds": 300,
		}
	}
	person := servedPAMReviewedOpen(t, h, requester, reviewerOne, reviewerTwo, "g1-person-session", pamRequest())
	agent := servedPAMReviewedOpen(t, h, agentToken, reviewerOne, reviewerTwo, "g1-agent-session", pamRequest())
	if person.Postgres == nil || agent.Postgres == nil {
		t.Fatalf("PAM sessions returned no PostgreSQL credential: %+v / %+v", person, agent)
	}
	assertPAMPostgresAccess(t, person.Postgres.DSN, true)

	database := "res:pam:postgres:pg-main"
	get := func(srv *servedHarness, path, token string, want int) []byte {
		t.Helper()
		status, body := secretsReq(t, srv, http.MethodGet, path, token, nil)
		if status != want {
			t.Fatalf("GET %s status=%d want=%d body=%s", path, status, want, body)
		}
		return body
	}
	reachersPath := "/api/v1/graph/reachers/" + url.PathEscape(database)
	pathQuery := func(from, to string) string {
		return "/api/v1/graph/path?" + url.Values{"from": {from}, "to": {to}}.Encode()
	}
	reachersBody := get(h, reachersPath, reader, http.StatusOK)
	var answer g1Reachers
	if err := json.Unmarshal(reachersBody, &answer); err != nil {
		t.Fatal(err)
	}
	if answer.Target.ID != database || answer.Target.Kind != "resource" {
		t.Fatalf("target = %+v", answer.Target)
	}
	grants := map[string]g1Grant{}
	for _, grant := range answer.Access {
		grants[grant.Credential.ID] = grant
	}
	if len(grants) != 2 {
		t.Fatalf("access rows = %+v, want the person's and the agent's PAM sessions", answer.Access)
	}
	wantApprovers := []string{
		"person:pam-reviewer-one|person|APPROVED|PAM approval decision|authoritative",
		"person:pam-reviewer-two|person|APPROVED|PAM approval decision|authoritative",
	}
	for sessionID, wantHolders := range map[string][]string{
		person.ID: {
			"person:pam-requester|person|HOLDS|PAM session requester|authoritative",
			"principal:pam-workload|workload|HOLDS|PAM session attested workload|authoritative",
		},
		agent.ID: {
			"aiagent:agent-7|ai-agent|HOLDS|PAM session requester|authoritative",
			"principal:pam-workload|workload|HOLDS|PAM session attested workload|authoritative",
		},
	} {
		grant, ok := grants["pam:"+sessionID]
		if !ok {
			t.Fatalf("session %s missing from who-can-reach: %+v", sessionID, answer.Access)
		}
		if grant.Credential.Kind != "credential" || grant.Credential.Attrs["credential_kind"] != "pam_session" ||
			grant.Credential.Attrs["approval_recorded"] != "true" || grant.Grant.Type != "GRANTS_ACCESS" ||
			grant.Grant.Source != "PAM session grant" || grant.Grant.Confidence != "authoritative" {
			t.Fatalf("session %s credential/grant = %+v / %+v", sessionID, grant.Credential, grant.Grant)
		}
		if got := g1Links(grant.Holders); !reflect.DeepEqual(got, wantHolders) {
			t.Fatalf("session %s holders = %v, want %v", sessionID, got, wantHolders)
		}
		if got := g1Links(grant.Approvers); !reflect.DeepEqual(got, wantApprovers) {
			t.Fatalf("session %s approvers = %v, want %v", sessionID, got, wantApprovers)
		}
	}
	for _, link := range grants["pam:"+person.ID].Holders {
		if link.Node.ID == "person:pam-requester" && link.Node.Name != "Rita Requester" {
			t.Fatalf("person node name = %q", link.Node.Name)
		}
	}
	if answer.Coverage.Note == "" || len(answer.Coverage.NotCovered) == 0 {
		t.Fatalf("coverage must state what the answer cannot see: %+v", answer.Coverage)
	}
	graphBody := get(h, "/api/v1/graph", reader, http.StatusOK)
	if strings.Contains(string(graphBody), "@example.test") {
		t.Fatal("the graph carries a member email; a person node names the subject and display name only")
	}
	var full struct {
		Nodes []g1Node `json:"nodes"`
		Edges []g1Edge `json:"edges"`
	}
	if err := json.Unmarshal(graphBody, &full); err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, n := range full.Nodes {
		kinds[n.Kind] = true
	}
	for _, want := range []string{"person", "role", "ai-agent"} {
		if !kinds[want] {
			t.Fatalf("graph has no %s node: %v", want, kinds)
		}
	}
	if !g1HasEdge(full.Edges, "aiagent:agent-7", "cert:"+agentIdentity.CertificateID, "HOLDS") ||
		!g1HasEdge(full.Edges, "person:pam-requester", "role:operator", "HAS_ROLE") {
		t.Fatal("graph lacks the AI agent's certificate or the requester's role")
	}

	personPath := get(h, pathQuery("person:pam-requester", database), reader, http.StatusOK)
	agentPath := get(h, pathQuery("aiagent:agent-7", database), reader, http.StatusOK)
	for body, want := range map[string][]string{
		string(personPath): {"person:pam-requester", "pam:" + person.ID, database},
		string(agentPath):  {"aiagent:agent-7", "pam:" + agent.ID, database},
	} {
		var resp struct {
			Path g1Path `json:"path"`
		}
		if err := json.Unmarshal([]byte(body), &resp); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, n := range resp.Path.Nodes {
			got = append(got, n.ID)
		}
		if !reflect.DeepEqual(got, want) || resp.Path.Edges[0].Type != "HOLDS" {
			t.Fatalf("path = %v (%+v), want %v", got, resp.Path.Edges, want)
		}
	}
	// An approver approved the access but does not hold it.
	get(h, pathQuery("person:pam-reviewer-one", database), reader, http.StatusNotFound)
	get(h, "/api/v1/graph/path?from=person:pam-requester", reader, http.StatusBadRequest)
	get(h, "/api/v1/graph/reachers/"+url.PathEscape("res:pam:postgres:missing"), reader, http.StatusNotFound)
	get(h, reachersPath, noGraph, http.StatusForbidden)
	get(h, pathQuery("person:pam-requester", database), noGraph, http.StatusForbidden)

	// A fresh assembly over the same PostgreSQL/event/signer spine answers the
	// same bytes, and so does a full rebuild of the read models from events.
	restarted, err := Build(t.Context(), Deps{
		Store: h.store, Log: h.log, Signer: h.signer, SignAuthorizer: h.authz,
		CACertFile: h.caFile, KEK: h.kek,
	})
	if err != nil {
		t.Fatalf("restart assembly: %v", err)
	}
	cleanupServedServer(t, restarted)
	restartedHTTP := httptest.NewServer(restarted.Handler())
	t.Cleanup(restartedHTTP.Close)
	cold := &servedHarness{srv: restarted, ts: restartedHTTP, store: h.store, log: h.log, tenant: h.tenant,
		signer: h.signer, authz: h.authz, caFile: h.caFile, kek: h.kek}
	assertSame := func(stage string) {
		t.Helper()
		for path, before := range map[string][]byte{
			reachersPath: reachersBody, "/api/v1/graph": graphBody,
			pathQuery("person:pam-requester", database): personPath,
			pathQuery("aiagent:agent-7", database):      agentPath,
		} {
			if after := get(cold, path, reader, http.StatusOK); string(after) != string(before) {
				t.Fatalf("%s changed %s:\nbefore=%s\nafter=%s", stage, path, before, after)
			}
		}
	}
	assertSame("cold restart")
	if err := h.srv.proj.Rebuild(t.Context(), h.log); err != nil {
		t.Fatalf("projection rebuild: %v", err)
	}
	assertSame("projection rebuild")
}

func g1Links(links []g1Link) []string {
	out := make([]string, 0, len(links))
	for _, l := range links {
		out = append(out, strings.Join([]string{l.Node.ID, l.Node.Kind, l.Edge.Type, l.Edge.Source, l.Edge.Confidence}, "|"))
	}
	return out
}

func g1HasEdge(edges []g1Edge, from, to, typ string) bool {
	for _, e := range edges {
		if e.From == from && e.To == to && e.Type == typ {
			return true
		}
	}
	return false
}
