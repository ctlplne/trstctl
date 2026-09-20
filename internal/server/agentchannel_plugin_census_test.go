// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/plugincensus"
	"trstctl.com/trstctl/internal/projections"
)

func TestSignedRelayPluginCensusIsTenantAgentBoundFreshAndReplayable(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork})
	plugins := []plugincensus.Entry{{
		Name: "partner", Digest: "sha256:" + repeatHex("a"), Publisher: "sha256:" + repeatHex("b"),
		ExecutionContext: plugincensus.ExecutionContextNetworkRelayWASM,
		Grants:           []plugincensus.Grant{{Capability: "net.dial", Constraints: []string{"appliance.internal:443"}}},
	}}
	issuedAt := time.Now().UTC().Add(-2 * time.Second).Unix()
	report, err := transport.SignedPluginCensus(h.identity.Identity(), h.tenant, h.agent, plugins, issuedAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{
		AgentID: "request-field-is-not-authority", Version: "relay-test", Status: "active", RelayPlugins: report,
	}); err != nil {
		t.Fatalf("valid signed census heartbeat: %v", err)
	}
	agentID := agentRowID(h.tenant, h.agent)
	assertPluginCensus := func(stage string) {
		t.Helper()
		row, err := h.store.GetAgent(ctx, h.tenant, agentID)
		if err != nil {
			t.Fatalf("%s: get projected agent: %v", stage, err)
		}
		if len(row.RelayPlugins) != 1 || row.RelayPlugins[0].Name != "partner" ||
			row.RelayPlugins[0].Publisher != plugins[0].Publisher || row.RelayPluginsReportedAt == nil ||
			row.RelayPluginsSignerFingerprint == "" || len(row.RelayPluginsSignature) == 0 || row.RelayPluginsStatement == "" {
			t.Fatalf("%s: projected plugin census = %+v", stage, row)
		}
	}
	assertPluginCensus("live")
	assertCatalog := func(stage string) {
		t.Helper()
		token := seedScopedToken(t, h.store, h.tenant, "connectors:read")
		code, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/connectors/catalog?limit=20", token, nil)
		if code != http.StatusOK {
			t.Fatalf("%s: connector catalog status=%d body=%s", stage, code, body)
		}
		for _, forbidden := range [][]byte{[]byte(`"signature":`), []byte(`"statement":`), report.Signature} {
			if bytes.Contains(body, forbidden) {
				t.Fatalf("%s: connector catalog leaked signed or byte-bearing evidence %q", stage, forbidden)
			}
		}
		var response struct {
			RelayPlugins []struct {
				AgentID           string               `json:"agent_id"`
				AgentName         string               `json:"agent_name"`
				ReportedAt        string               `json:"reported_at"`
				SignerFingerprint string               `json:"signer_fingerprint"`
				SignatureVerified bool                 `json:"signature_verified"`
				MetadataOnly      bool                 `json:"metadata_only"`
				Plugins           []plugincensus.Entry `json:"plugins"`
			} `json:"relay_plugins"`
		}
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatalf("%s: decode catalog: %v (%s)", stage, err, body)
		}
		if len(response.RelayPlugins) != 1 || response.RelayPlugins[0].AgentID != agentID ||
			response.RelayPlugins[0].AgentName != h.agent || response.RelayPlugins[0].ReportedAt == "" ||
			response.RelayPlugins[0].SignerFingerprint == "" || !response.RelayPlugins[0].SignatureVerified ||
			!response.RelayPlugins[0].MetadataOnly || len(response.RelayPlugins[0].Plugins) != 1 ||
			response.RelayPlugins[0].Plugins[0].Grants[0].Constraints[0] != "appliance.internal:443" {
			t.Fatalf("%s: served relay plugin catalog = %+v", stage, response.RelayPlugins)
		}
	}
	assertCatalog("live")

	// The signature binds every module field. Changing a digest after signing is
	// a refusal and cannot replace the last accepted view.
	tampered := *report
	tampered.Plugins = append([]plugincensus.Entry(nil), report.Plugins...)
	tampered.Plugins[0].Digest = "sha256:" + repeatHex("c")
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{Status: "active", RelayPlugins: &tampered}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("tampered census error = %v, want PermissionDenied", err)
	}
	assertPluginCensus("after tamper")

	// A valid signature for another tenant cannot be replayed on this tenant's
	// authenticated channel because tenant is inside the signed statement and is
	// reconstructed from the peer certificate by the server.
	crossTenant, err := transport.SignedPluginCensus(h.identity.Identity(),
		"22222222-2222-2222-2222-222222222222", h.agent, plugins, time.Now().UTC().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{Status: "active", RelayPlugins: crossTenant}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-tenant census error = %v, want PermissionDenied", err)
	}

	stale, err := transport.SignedPluginCensus(h.identity.Identity(), h.tenant, h.agent, plugins, issuedAt-1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{Status: "active", RelayPlugins: stale}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stale census error = %v, want FailedPrecondition", err)
	}

	if err := projections.New(h.store).Rebuild(ctx, h.log); err != nil {
		t.Fatalf("rebuild projections: %v", err)
	}
	assertPluginCensus("after restart-style replay")
	assertCatalog("after restart-style replay")
	if _, err := h.store.GetAgent(ctx, "33333333-3333-3333-3333-333333333333", agentID); err == nil {
		t.Fatal("another tenant read the relay plugin census")
	}
}

func TestHostAgentCannotReportRelayPluginCensus(t *testing.T) {
	h := newRoleHarness(t, []string{mtls.AgentRoleHost})
	report, err := transport.SignedPluginCensus(h.identity.Identity(), h.tenant, h.agent, []plugincensus.Entry{}, time.Now().UTC().Unix())
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.client.Heartbeat(context.Background(), &transport.HeartbeatRequest{Status: "active", RelayPlugins: report})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("host plugin census error = %v, want PermissionDenied", err)
	}
}

func repeatHex(v string) string {
	var out string
	for range 64 {
		out += v
	}
	return out
}
