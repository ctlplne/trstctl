// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"testing"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// SW-NULC: an enrolled agent (mTLS client certificate, no tenant-user credential)
// reports a heartbeat whose Version / Status carry U+0000. recordHeartbeat appends
// agent.heartbeat to the immutable log and only then projects it (agents.version /
// agents.status are text); PostgreSQL refuses the NUL (SQLSTATE 22021). The test
// PASSES when the product rejects the byte before the append; it FAILS when the
// event is retained in the log or the restart Build fails.
func TestCR893EnrolledAgentHeartbeatTextCannotPoisonLog(t *testing.T) {
	ctx := t.Context()
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{"revocation.probe"}, func(*Deps) {})
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "v1.2.3", Status: "active"}); err != nil {
		t.Fatalf("control heartbeat: %v", err)
	}
	retained := 0
	for _, c := range []struct {
		name, version, status string
	}{
		{"version", "1.0\x00poison", "active"},
		{"status", "v1.2.3", "ac\x00tive"},
	} {
		before, err := h.log.LastSequence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, herr := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: c.version, Status: c.status})
		after, err := h.log.LastSequence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: heartbeat err=%v; log grew by %d", c.name, herr, after-before)
		if herr != nil && after > before {
			retained++
			t.Errorf("SWNULC %s: heartbeat refused (%v) but %d agent.heartbeat event(s) stay in the immutable log", c.name, herr, after-before)
		}
	}
	h.ts.Close()
	restarted, err := Build(ctx, Deps{Store: h.store, Log: h.log, Signer: h.signer, SignAuthorizer: h.authz, CACertFile: h.caFile, Protocols: config.Protocols{}})
	if err != nil {
		t.Errorf("SWNULC: restart Build failed for every tenant after %d retained poison event(s): %v", retained, err)
		return
	}
	cleanupServedServer(t, restarted)
}

func TestCR893EnrolledAgentInventoryTextCannotPoisonLog(t *testing.T) {
	ctx := t.Context()
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, nil)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "v1.2.3", Status: "active"}); err != nil {
		t.Fatalf("control heartbeat: %v", err)
	}
	before, err := h.log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, callErr := h.client.ReportInventory(ctx, &transport.InventoryRequest{
		SourceKind: "filesystem",
		Findings: []transport.InventoryFinding{{
			Kind: "x509_certificate", Ref: "/etc/ssl/private/leaf\x00.pem",
			Provenance: "filesystem:leaf", Fingerprint: "sha256:leaf", RiskScore: 35,
			Metadata: map[string]string{"key_store": "filesystem"},
		}},
	})
	after, err := h.log.LastSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if callErr == nil {
		t.Error("inventory report with NUL ref was accepted")
	}
	if after != before {
		t.Errorf("NUL inventory report retained %d event(s): %v", after-before, callErr)
	}
	h.ts.Close()
	restarted, err := Build(ctx, Deps{Store: h.store, Log: h.log, Signer: h.signer, SignAuthorizer: h.authz, CACertFile: h.caFile, Protocols: config.Protocols{}})
	if err != nil {
		t.Errorf("restart Build failed after NUL inventory report: %v", err)
		return
	}
	cleanupServedServer(t, restarted)
}
