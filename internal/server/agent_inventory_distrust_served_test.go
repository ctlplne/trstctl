// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
)

// Part 4 Done-when: a host trust store holding emSign ECC Root CA - G3 shows a
// finding. The control plane matches what an agent reported against its own
// distrust list (the agent may be older, or the entry newer), replaces any
// distrust claim in the report, keeps the agent's weak-key reasons, and raises
// the risk.
func TestServedAgentInventoryRatesDistrustedTrustStoreRoots(t *testing.T) {
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

	a := enrollAgent(t, h, "edge-agent-distrust", "agent.trstctl.local")
	creds, err := a.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(ln.Addr().String(), creds)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := transport.NewAgentClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	registerInventoryAgent(t, client)

	inv, err := client.ReportInventory(ctx, &transport.InventoryRequest{
		SourceKind: "trust-store",
		Findings: []transport.InventoryFinding{
			{
				// An older agent: no rating at all, only the identity it always sent.
				Kind: "trust-store", Ref: "trust-store:os:/etc/ssl/certs/emSign_ECC_Root_CA_-_G3.pem",
				Provenance:  "trust-store:/etc/ssl/certs/emSign_ECC_Root_CA_-_G3.pem",
				Fingerprint: "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b", RiskScore: 20,
				Metadata: map[string]string{"subject": "CN=emSign ECC Root CA - G3", "spki_sha256": "8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782"},
			},
			{
				// A report claiming a distrust the server's list does not hold.
				Kind: "trust-store", Ref: "trust-store:os:/etc/ssl/certs/clean.pem", Provenance: "trust-store:/etc/ssl/certs/clean.pem",
				Fingerprint: "1111111111111111111111111111111111111111111111111111111111111111", RiskScore: 20,
				Metadata: map[string]string{"subject": "CN=Clean Root", "spki_sha256": "2222222222222222222222222222222222222222222222222222222222222222", "distrust_entry": "Made Up CA", "distrust_how": "itself"},
			},
		},
	})
	if err != nil || inv.Recorded != 2 {
		t.Fatalf("report trust-store inventory: %+v %v", inv, err)
	}
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:read")
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?run_id="+inv.RunID, tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list findings: %d %s", status, body)
	}
	var out struct {
		Items []struct {
			Ref       string            `json:"ref"`
			RiskScore int               `json:"risk_score"`
			Metadata  map[string]string `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	byRef := map[string]int{}
	for i, item := range out.Items {
		byRef[item.Ref] = i
	}
	root := out.Items[byRef["trust-store:os:/etc/ssl/certs/emSign_ECC_Root_CA_-_G3.pem"]]
	if root.Metadata["distrust_entry"] != "emSign ECC Root CA - G3" || root.Metadata["distrust_how"] != "itself" || root.RiskScore < 95 || root.Metadata["host"] == "" {
		t.Fatalf("emSign ECC Root CA - G3 in a host trust store: %+v", root)
	}
	clean := out.Items[byRef["trust-store:os:/etc/ssl/certs/clean.pem"]]
	if clean.Metadata["distrust_entry"] != "" || clean.RiskScore != 20 {
		t.Fatalf("an agent's distrust claim survived: %+v", clean)
	}
}
