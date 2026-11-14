// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// Q4-L3 Done-when: an agent broker scope's action is part of the graph. Two
// agents get identities on the same tool, one with tool:inventory.read and one
// with tool:inventory.write (and a third with both). Each certificate's access
// grant to res:agent-scope:tool:inventory carries its actions; who can reach
// the tool for write lists the writer and the agent holding both, not the
// reader; for read the reader and both; with no action all three. The evidence
// path from the requester shows the action, and an action that is not a scope
// action is refused.
func TestServedWhoCanReachAToolForOneActionQ4L3(t *testing.T) {
	h, owner, readerBody := servedPublicBrokerRevocationFixture(t, func(d *Deps) { d.AgentBroker.PolicyModule = q4l3BrokerPolicy })
	issuer := seedScopedTokenSubject(t, h.store, h.tenant, "q4l3-requester@ops.example", "certs:issue", "certs:read", "identities:write")
	viewer := seedScopedTokenSubject(t, h.store, h.tenant, "q4l3-viewer", "certs:read", "graph:read", "access:read")

	writerBody := servedBrokerAgentIssueBody(t, h, owner, "q4l3-writer")
	writerBody["scopes"] = []string{"tool:inventory.write"}
	bothBody := servedBrokerAgentIssueBody(t, h, owner, "q4l3-both")
	bothBody["scopes"] = []string{"tool:inventory.read", "tool:inventory.write"}
	readerBody["agent_id"] = "q4l3-reader" // the fixture's body reads: tool:inventory.read
	certs := map[string]string{}
	for agent, body := range map[string]map[string]any{"q4l3-reader": readerBody, "q4l3-writer": writerBody, "q4l3-both": bothBody} {
		certs[agent] = servedBrokerIssue(t, h, issuer, agent+"-issue", body, http.StatusCreated).CertificateID
	}

	type edge struct {
		From    string   `json:"from"`
		To      string   `json:"to"`
		Type    string   `json:"type"`
		Actions []string `json:"actions"`
	}
	var reachers struct {
		Action string `json:"action"`
		Access []struct {
			Credential struct {
				ID string `json:"id"`
			} `json:"credential"`
			Grant edge `json:"grant"`
		} `json:"access"`
	}
	tool := "res:agent-scope:tool:inventory"
	answer := func(action string) map[string][]string {
		t.Helper()
		query := "/api/v1/graph/reachers/" + url.PathEscape(tool)
		if action != "" {
			query += "?" + url.Values{"action": {action}}.Encode()
		}
		status, raw := secretsReq(t, h, http.MethodGet, query, viewer, nil)
		reachers.Access = nil
		if status != http.StatusOK || json.Unmarshal(raw, &reachers) != nil || reachers.Action != action {
			t.Fatalf("who can reach the tool for %q: HTTP %d %s", action, status, raw)
		}
		out := map[string][]string{}
		for _, grant := range reachers.Access {
			if grant.Grant.Type != "GRANTS_ACCESS" || grant.Grant.To != tool {
				t.Fatalf("grant = %+v", grant.Grant)
			}
			out[grant.Credential.ID] = grant.Grant.Actions
		}
		return out
	}
	credential := func(agent string) string { return "cert:" + certs[agent] }

	all := answer("")
	if len(all) != 3 || !slices.Equal(all[credential("q4l3-reader")], []string{"read"}) ||
		!slices.Equal(all[credential("q4l3-writer")], []string{"write"}) ||
		!slices.Equal(all[credential("q4l3-both")], []string{"read", "write"}) {
		t.Fatalf("grants on the tool = %v", all)
	}
	for action, want := range map[string][]string{
		"write": {credential("q4l3-both"), credential("q4l3-writer")},
		"read":  {credential("q4l3-both"), credential("q4l3-reader")},
	} {
		got := answer(action)
		ids := make([]string, 0, len(got))
		for id := range got {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		slices.Sort(want)
		if !slices.Equal(ids, want) {
			t.Fatalf("who can reach the tool for %s = %v, want %v", action, ids, want)
		}
	}

	// The evidence path from the requester shows the action on its grant.
	pathQuery := "/api/v1/graph/path?" + url.Values{"from": {"aiagent:q4l3-writer"}, "to": {tool}}.Encode()
	status, raw := secretsReq(t, h, http.MethodGet, pathQuery, viewer, nil)
	var path struct {
		Path struct {
			Edges []edge `json:"edges"`
		} `json:"path"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &path) != nil || len(path.Path.Edges) != 2 ||
		!slices.Equal(path.Path.Edges[1].Actions, []string{"write"}) {
		t.Fatalf("the writer's path: HTTP %d %s", status, raw)
	}

	if status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/graph/reachers/"+url.PathEscape(tool)+"?action="+url.QueryEscape("rm -rf"), viewer, nil); status != http.StatusBadRequest || !strings.Contains(string(raw), "scope action") {
		t.Fatalf("an action with a space = HTTP %d %s, want 400", status, raw)
	}
	t.Logf("Q4L3_OK reader=%s writer=%s both=%s", certs["q4l3-reader"], certs["q4l3-writer"], certs["q4l3-both"])
}

// q4l3BrokerPolicy lets this test's three agents be issued identities.
const q4l3BrokerPolicy = `package trstctl.policy

default allow := false
default reason := "scope not permitted"

allow if {
	input.action == "issue"
	startswith(input.attrs.agent_id, "q4l3-")
}
`
