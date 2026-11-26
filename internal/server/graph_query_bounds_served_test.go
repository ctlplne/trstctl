// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestServedGraphQueryRejectsExcessiveHops(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	token := seedScopedToken(t, h.store, h.tenant, "graph:read")
	query := "MATCH (n0)"
	for i := 1; i <= 9; i++ {
		query += fmt.Sprintf("-[:STEP]->(n%d)", i)
	}
	query += " RETURN n9"
	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/graph/query", token, map[string]string{"query": query})
	if status != http.StatusBadRequest || !strings.Contains(string(body), "hops") {
		t.Fatalf("nine-hop graph query: HTTP %d %s, want bounded 400", status, body)
	}
}
