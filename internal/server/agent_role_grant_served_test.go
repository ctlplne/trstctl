// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// A191: an operator's grant changes an agent's role at its next renewal, with
// no re-enrollment. A host agent cannot claim relay work; an operator holding
// agents:relay.grant (agents:write alone is refused) grants it the network
// role; its heartbeat asks it to renew; the renewal signs the granted roles
// and records which grant it signed; and on its renewed certificate the agent
// claims the relay work it was refused. A renewal CSR asking for a role the
// agent is not being given is refused by name, before and after the grant.
func TestServedRoleGrantMakesAHostAgentARelayAtItsNextRenewal(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarnessNamedWithEventOptions(t, "a191-edge", []string{mtls.AgentRoleHost}, []string{"endpoint.verify"}, nil)
	agentID := agentRowID(h.tenant, h.agent)
	beat := func(client *transport.AgentClient) *transport.HeartbeatResponse {
		t.Helper()
		resp, err := client.Heartbeat(ctx, &transport.HeartbeatRequest{Version: "a191", Status: "active"})
		if err != nil {
			t.Fatalf("heartbeat: %v", err)
		}
		return resp
	}
	if resp := beat(h.client); resp.RenewCertificate {
		t.Fatal("a heartbeat asked for a renewal before any grant")
	}
	seedRoleJob(t, ctx, h, "endpoint.verify", "a191-verify")
	if claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"endpoint.verify"}, Limit: 5, LeaseSeconds: 60}); err != nil || len(claimed.Jobs) != 0 {
		t.Fatalf("host agent claim of relay work = %+v, %v; want none", claimed, err)
	}

	askingFor := func(role string) []byte {
		t.Helper()
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Destroy)
		csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
			CommonName: h.agent, URIs: []string{mtls.AgentRoleSPIFFEID(h.tenant, h.agent, role)},
		}, key)
		if err != nil {
			t.Fatal(err)
		}
		return csr
	}
	if _, err := h.client.Renew(ctx, &transport.RenewRequest{CSRDER: askingFor(mtls.AgentRoleNetwork)}); status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "network") {
		t.Fatalf("a host agent's CSR asking for the network role = %v, want a refusal naming it", err)
	}

	path := "/api/v1/agents/" + agentID + "/roles"
	grant := map[string]any{"roles": []string{mtls.AgentRoleHost, mtls.AgentRoleNetwork}, "reason": "front the appliances in plant 7"}
	writer := seedScopedToken(t, h.store, h.tenant, "agents:write")
	if code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, path, writer, "a191-writer", grant); code != http.StatusForbidden {
		t.Fatalf("agents:write alone granting the network role = %d %s, want 403", code, body)
	}
	granter := seedScopedToken(t, h.store, h.tenant, "agents:relay.grant")
	if code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, path, granter, "a191-unknown", map[string]any{"roles": []string{"admin"}}); code != http.StatusBadRequest {
		t.Fatalf("granting an unknown role = %d %s, want 400", code, body)
	}
	code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, path, granter, "a191-grant", grant)
	if code != http.StatusOK {
		t.Fatalf("grant = %d %s", code, body)
	}
	var granted struct {
		Roles     []string `json:"roles"`
		RoleGrant *struct {
			Roles   []string `json:"roles"`
			State   string   `json:"state"`
			EventID string   `json:"event_id"`
		} `json:"role_grant"`
	}
	if err := json.Unmarshal(body, &granted); err != nil || granted.RoleGrant == nil || granted.RoleGrant.State != "pending" ||
		!slices.Equal(granted.RoleGrant.Roles, []string{mtls.AgentRoleHost, mtls.AgentRoleNetwork}) || !slices.Equal(granted.Roles, []string{mtls.AgentRoleHost}) {
		t.Fatalf("grant response = %s (%v); want a pending grant beside the certificate's host role", body, err)
	}
	if !h.hasEvent(t, projections.EventAgentRolesGranted) {
		t.Fatal("the grant was not recorded in the event log")
	}
	if resp := beat(h.client); !resp.RenewCertificate {
		t.Fatal("the heartbeat did not ask the agent to renew for the pending grant")
	}
	if _, err := h.client.Renew(ctx, &transport.RenewRequest{CSRDER: askingFor("admin")}); status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "admin") {
		t.Fatalf("a CSR asking for an unknown role = %v, want a refusal naming it", err)
	}

	renewed, err := mtls.GenerateAgentKey(h.agent)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := renewed.CSR()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := h.client.Renew(ctx, &transport.RenewRequest{CSRDER: csr})
	if err != nil {
		t.Fatalf("renewal: %v", err)
	}
	if err := renewed.UseCertificate(resp.CertChainPEM); err != nil {
		t.Fatal(err)
	}
	if roles := renewed.Roles(); !slices.Equal(roles, []string{mtls.AgentRoleHost, mtls.AgentRoleNetwork}) {
		t.Fatalf("renewed certificate roles = %v, want the granted host and network", roles)
	}
	stored, found, err := h.store.AgentRoleGrant(ctx, h.tenant, agentID)
	if err != nil || !found || stored.Pending() || stored.AppliedSerial != renewed.Serial() || stored.EventID != granted.RoleGrant.EventID {
		t.Fatalf("grant after renewal = %+v, %v, %v; want applied at serial %s", stored, found, err, renewed.Serial())
	}
	var renewal projections.AgentCertRenewed
	if err := h.log.Replay(ctx, 0, func(e events.Event) error {
		if e.Type == projections.EventAgentCertRenewed && e.TenantID == h.tenant && e.SchemaVersion == projections.AgentCertRenewedRolesSchemaVersion {
			return json.Unmarshal(e.Data, &renewal)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if renewal.NewSerial != renewed.Serial() || renewal.RoleGrantEventID != stored.EventID || !slices.Equal(renewal.Roles, []string{mtls.AgentRoleHost, mtls.AgentRoleNetwork}) {
		t.Fatalf("renewal event = %+v; want the signed roles and the grant it applied", renewal)
	}
	if resp := beat(h.client); resp.RenewCertificate {
		t.Fatal("the heartbeat still asks for a renewal after the grant was signed")
	}

	creds, err := mtls.AgentClientCredentials(renewed, h.srv.AgentCACertPEM(), h.serverName, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(h.channelAddr, creds)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	relay := transport.NewAgentClient(conn)
	beat(relay)
	claimCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if claimed, err := relay.ClaimJobs(claimCtx, &transport.ClaimJobsRequest{Kinds: []string{"endpoint.verify"}, Limit: 5, LeaseSeconds: 60}); err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("the renewed agent's claim of relay work = %+v, %v; want the job it was refused", claimed, err)
	}

	reader := seedScopedToken(t, h.store, h.tenant, "agents:read")
	code, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/agents", reader, nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"state":"applied"`) || !strings.Contains(string(body), `"applied_serial":"`+renewed.Serial()+`"`) {
		t.Fatalf("agent list = %d %s; want the applied grant", code, body)
	}
}
