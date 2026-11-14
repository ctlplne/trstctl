// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"net"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/discovery"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
)

// P14-L2-O1: an agent that reports the same finding again at another urgent
// score has the report recorded — the finding at its new score, its urgent
// alert the one already raised — instead of the whole report failing on the
// alert's key and the host's inventory standing still.
func TestServedAnAgentFindingReobservedAtAnotherUrgentScoreIsRecordedP14L2O1(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withAgentChannel)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	chCtx, chCancel := context.WithCancel(context.Background())
	t.Cleanup(chCancel)
	chDone := make(chan struct{})
	go func() { defer close(chDone); h.srv.serveAgentChannel(chCtx, ln) }()
	t.Cleanup(func() { chCancel(); <-chDone })
	a := enrollAgent(t, h, "edge-agent-p14l2o1", "agent.trstctl.local")
	creds, err := a.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(ln.Addr().String(), creds)
	if err != nil {
		t.Fatalf("dial agent channel: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := transport.NewAgentClient(conn)
	registerInventoryAgent(t, client)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ref := "/home/p14l2o1/.config/assistant/config.json#tracker"
	finding := func(risk int) []transport.InventoryFinding {
		return []transport.InventoryFinding{{Kind: discovery.FindingKindMCPServer, Ref: ref,
			Provenance: discovery.SourceMCPClientConfig + ":/home/p14l2o1/.config/assistant/config.json", Fingerprint: "p14l2o1-tracker",
			RiskScore: risk, Metadata: map[string]string{"server_name": "tracker", "transport": "stdio", "command": "tracker-mcp", // #nosec G101 -- MCP finding metadata naming a field, no credential (CWE-798)
				"static_credential": "true", "credential_fields": "env:TRACKER_TOKEN", "credential_values": "not_collected"}}}
	}
	for _, risk := range []int{80, 95} {
		resp, err := client.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: discovery.SourceMCPClientConfig, Findings: finding(risk)})
		if err != nil || resp.Recorded != 1 || resp.Rejected != 0 {
			t.Fatalf("report at risk %d = %+v %v", risk, resp, err)
		}
	}
	var id string
	var risk, alerts int
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT id::text, risk_score FROM discovery_findings WHERE tenant_id = $1 AND ref = $2`,
		h.tenant, ref).Scan(&id, &risk); err != nil {
		t.Fatal(err)
	}
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`,
		h.tenant, "urgent-risk:"+id).Scan(&alerts); err != nil {
		t.Fatal(err)
	}
	if risk != 95 || alerts != 1 {
		t.Fatalf("the finding reads risk %d with %d urgent alerts, want 95 and the first alert alone", risk, alerts)
	}
}
