// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"encoding/json"
	"github.com/google/uuid"
	"net/http"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

func TestServedLocalAdministratorHostPickerA268(t *testing.T) {
	ctx := t.Context()
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, nil, func(d *Deps) {
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	enrolled := func(name, role string) string {
		t.Helper()
		a := enrollAgentWithRoles(t, h.servedHarness, name, h.serverName, []string{role})
		credentials, err := a.Credentials()
		if err != nil {
			t.Fatal(err)
		}
		conn, err := transport.Dial(h.channelAddr, credentials)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		if _, err := transport.NewAgentClient(conn).Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: name, Version: "test-1.0", Status: "active"}); err != nil {
			t.Fatal(err)
		}
		return agentRowID(h.tenant, name)
	}
	second := enrolled("owned-second-host", mtls.AgentRoleHost)
	gateway := enrolled("owned-gateway", mtls.AgentRoleGateway)
	network := enrolled("owned-network", mtls.AgentRoleNetwork)
	retired := enrolled("owned-offboarded-host", mtls.AgentRoleHost)
	if _, err := h.store.SystemPool().Exec(ctx, `UPDATE agents SET offboarded_at=now() WHERE tenant_id=$1 AND id=$2`, h.tenant, retired); err != nil {
		t.Fatal(err)
	}
	token := seedScopedTokenSubject(t, h.store, h.tenant, "pam-inventory-reader", "access:read")
	if code, _ := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/agents", token, nil); code != http.StatusForbidden {
		t.Fatal("host picker proof unexpectedly has general agent inventory scope", code)
	}
	type host struct {
		ID, Name, Status string
		LastSeenAt       *time.Time `json:"last_seen_at"`
	}
	type page struct {
		Items      []host `json:"items"`
		NextCursor string `json:"next_cursor"`
	}
	root := "/api/v1/access/discovery/windows-hosts"
	read := func(after string) page {
		t.Helper()
		code, body := secretsReq(t, h.servedHarness, http.MethodGet, root+"?limit=1&after="+after, token, nil)
		var result page
		if code != http.StatusOK || json.Unmarshal(body, &result) != nil || len(result.Items) != 1 || result.Items[0].LastSeenAt == nil {
			t.Fatalf("eligible host page status=%d body=%s", code, body)
		}
		for _, field := range []string{`"relay_plugins"`, `"revocation_caches"`, `"roles"`, `"tenant_id"`} {
			if strings.Contains(string(body), field) {
				t.Fatal("picker exposed unrelated agent payload", field)
			}
		}
		return result
	}
	first := read("")
	if first.NextCursor == "" {
		t.Fatal("picker hid its next page")
	}
	last := read(first.NextCursor)
	if last.NextCursor != "" || last.Items[0].ID == first.Items[0].ID {
		t.Fatal("picker repeated a host or invented a third page")
	}
	seen := map[string]bool{first.Items[0].ID: true, last.Items[0].ID: true}
	if !seen[agentRowID(h.tenant, h.agent)] || !seen[second] || seen[gateway] || seen[network] || seen[retired] {
		t.Fatal("host eligibility crossed role or offboarding boundary")
	}
	other := uuid.NewString()
	registerServedTenantID(t, h.servedHarness, other, "native host picker isolation")
	otherToken := seedScopedToken(t, h.store, other, "access:read")
	code, body := secretsReq(t, h.servedHarness, http.MethodGet, root, otherToken, nil)
	var foreign page
	if code != http.StatusOK || json.Unmarshal(body, &foreign) != nil || len(foreign.Items) != 0 {
		t.Fatal("another tenant saw enrolled native hosts", code)
	}
	for _, query := range []string{"?limit=0", "?limit=101", "?after=not-a-host"} {
		if code, _ := secretsReq(t, h.servedHarness, http.MethodGet, root+query, token, nil); code != http.StatusBadRequest {
			t.Fatal("unbounded or malformed host page was accepted", query, code)
		}
	}
}
