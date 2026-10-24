// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/weakkey"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// B11-L3: the product records an agent's inventory, a secret scan, the
// weak-key audit and an endpoint-chain finding as discovery runs that finish
// in the call that queues them. Boot reconciliation restores missing commands
// from retained queued events, and restored no-op discovery.run jobs for every
// such run (the batch-11 lab held twelve after its restarts). A finished run
// needs no job; an unfinished run whose job was lost is still restored, as
// TestServedADCSInventory proves for the relay path.
func TestServedReconcileRestoresNoJobForFinishedDiscoveryRuns(t *testing.T) {
	h := newRoleHarness(t, []string{mtls.AgentRoleHost})
	ctx := t.Context()
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "b12-test", Status: "active"}); err != nil {
		t.Fatalf("register the inventory agent: %v", err)
	}
	inventory, _, _, err := h.srv.orch.RecordAgentInventory(ctx, h.tenant, h.agent, agentRowID(h.tenant, h.agent), "trust-store-b12",
		[]store.DiscoveryFinding{{Kind: "trust-store", Ref: "/etc/ssl/certs/b12"}})
	if err != nil {
		t.Fatal(err)
	}
	scan, _, _, err := h.srv.orch.RecordSecretScan(ctx, h.tenant, "b12-scanner", "repo://b12", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := h.srv.orch.RecordWeakKeyAudit(ctx, h.tenant, weakkey.SharedFactorReport{}, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.orch.RecordEndpointChainMismatch(ctx, h.tenant, "b12-chain-job", orchestrator.EndpointChainMismatch{
		EndpointID: "edge", Address: "127.0.0.1:8443", ServerName: "edge.example.test", Connector: "nginx", Target: "edge",
		LeafFingerprint: strings.Repeat("a", 64), ObservedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	var chain string
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT r.id::text FROM discovery_runs r
		JOIN discovery_sources s ON s.tenant_id = r.tenant_id AND s.id = r.source_id
		WHERE r.tenant_id = $1 AND s.kind = 'endpoint_chain_verification'`, h.tenant).Scan(&chain); err != nil {
		t.Fatal(err)
	}
	runs := []string{inventory.ID, scan.ID, audit.ID, chain}
	for _, id := range runs {
		run, err := h.store.GetDiscoveryRun(ctx, h.tenant, id)
		if err != nil || run.Status != "succeeded" {
			t.Fatalf("recorded run %s = %+v (err=%v); want it finished", id, run, err)
		}
	}

	if _, err := h.srv.orch.ReconcileOutbox(ctx, h.srv.log); err != nil {
		t.Fatalf("reconcile outbox: %v", err)
	}
	var jobs int
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination = 'discovery.run'
		AND convert_from(payload, 'UTF8')::jsonb->>'id' = ANY($2)`, h.tenant, runs).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if jobs != 0 {
		t.Fatalf("reconciliation restored %d discovery.run jobs for finished recorded runs", jobs)
	}
}
