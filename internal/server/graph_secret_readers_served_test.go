// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// G1-L4 Done-when (served): a reader holding secrets:read sees the secret
// store in the graph — a scope per project environment and the store's root,
// the open scopes' secrets, and who may read each scope: a token with
// secrets:read reads the open scopes, and the restricted environment only
// its granted member's token. A restricted environment's secret names never
// appear, and a reader without secrets:read sees no scope and no name.
func TestServedGraphShowsWhoMayReadSecretsG1L4(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil))
	registerServedTenant(t, h, "G1-L4 secret readers tenant")
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "g1l4-admin", "access:write", "secrets:read", "secrets:write")
	seedScopedTokenSubject(t, h.store, h.tenant, "g1l4-member", "secrets:read")
	seedScopedTokenSubject(t, h.store, h.tenant, "g1l4-outsider", "secrets:read")
	reader := seedScopedTokenSubject(t, h.store, h.tenant, "g1l4-reader", "graph:read", "access:read", "secrets:read")
	noSecrets := seedScopedTokenSubject(t, h.store, h.tenant, "g1l4-graph-only", "graph:read", "access:read")
	call := func(method, path string, body any, want int) {
		t.Helper()
		status, raw := secretsReqKey(t, h, method, path, admin, fmt.Sprintf("g1l4-%d", time.Now().UnixNano()), body)
		if status != want {
			t.Fatalf("%s %s: HTTP %d %s, want %d", method, path, status, raw, want)
		}
	}
	call(http.MethodPost, "/api/v1/secrets/projects", map[string]any{"slug": "g1l4", "environments": []any{
		map[string]any{"slug": "dev"}, map[string]any{"slug": "prod", "restricted": true},
	}}, http.StatusCreated)
	call(http.MethodPut, "/api/v1/secrets/projects/g1l4/members/g1l4-member", map[string]any{"role": "developer", "environments": []string{"prod"}}, http.StatusOK)
	call(http.MethodPut, "/api/v1/secrets/projects/g1l4/members/g1l4-admin", map[string]any{"role": "admin", "environments": []string{"prod"}}, http.StatusOK)
	call(http.MethodPost, "/api/v1/secrets/store", map[string]any{"name": "g1l4/dev/db-password", "value": "g1l4-dev-value"}, http.StatusCreated)
	call(http.MethodPost, "/api/v1/secrets/store", map[string]any{"name": "g1l4/prod/payments-signer", "value": "g1l4-prod-value"}, http.StatusCreated)
	call(http.MethodPost, "/api/v1/secrets/store", map[string]any{"name": "standalone", "value": "g1l4-root-value"}, http.StatusCreated)

	type node struct {
		ID    string            `json:"id"`
		Kind  string            `json:"kind"`
		Name  string            `json:"name"`
		Attrs map[string]string `json:"attrs"`
	}
	type edge struct {
		From string `json:"from"`
		To   string `json:"to"`
		Type string `json:"type"`
	}
	read := func(tok string) (map[string]node, map[string]bool, []byte) {
		t.Helper()
		status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/graph", tok, nil)
		var body struct {
			Nodes []node `json:"nodes"`
			Edges []edge `json:"edges"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &body) != nil {
			t.Fatalf("graph: HTTP %d %s", status, raw)
		}
		nodes, edges := map[string]node{}, map[string]bool{}
		for _, n := range body.Nodes {
			nodes[n.ID] = n
		}
		for _, e := range body.Edges {
			edges[e.From+" "+e.Type+" "+e.To] = true
		}
		return nodes, edges, raw
	}
	tokenNode := func(nodes map[string]node, subject string) string {
		t.Helper()
		for id, n := range nodes {
			if n.Attrs["credential_kind"] == "api_token" && n.Attrs["subject"] == subject {
				return id
			}
		}
		t.Fatalf("no token node for %s", subject)
		return ""
	}
	nodes, edges, raw := read(reader)
	dev, prod, root := "res:secret-scope:g1l4/dev", "res:secret-scope:g1l4/prod", "res:secret-store"
	if nodes[prod].Attrs["restricted"] != "true" || nodes[dev].Attrs["restricted"] != "false" || nodes[root].Kind != "resource" {
		t.Fatalf("scopes: dev %+v prod %+v root %+v", nodes[dev], nodes[prod], nodes[root])
	}
	member, outsider := tokenNode(nodes, "g1l4-member"), tokenNode(nodes, "g1l4-outsider")
	for _, want := range []string{
		dev + " CONTAINS secret:g1l4/dev/db-password",
		root + " CONTAINS secret:standalone",
		member + " CAN_READ " + dev,
		member + " CAN_READ " + prod,
		outsider + " CAN_READ " + dev,
		outsider + " CAN_READ " + root,
	} {
		if !edges[want] {
			t.Fatalf("missing edge %q in %s", want, raw)
		}
	}
	if edges[outsider+" CAN_READ "+prod] {
		t.Fatal("a token whose subject is no member reads the restricted environment")
	}
	if bytes.Contains(raw, []byte("payments-signer")) {
		t.Fatal("the graph names a secret in a restricted environment")
	}
	if _, _, raw := read(noSecrets); bytes.Contains(raw, []byte("secret-scope")) || bytes.Contains(raw, []byte("db-password")) ||
		bytes.Contains(raw, []byte("res:secret-store")) {
		t.Fatalf("a reader without secrets:read sees the secret store: %s", raw)
	}
	t.Logf("G1L4_SECRET_READERS_OK scopes=%d", 3)
}
