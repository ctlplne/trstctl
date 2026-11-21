// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// v8Enroll bootstraps a fresh key under cn through the served POST
// /enroll/bootstrap with the token alone (no bearer): what a holder of a leaked
// or handed-over bootstrap token can do.
func v8Enroll(t *testing.T, h *servedHarness, token, cn string) (*mtls.AgentIdentity, int, []byte) {
	t.Helper()
	id, err := mtls.GenerateAgentKey(cn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Destroy)
	csr, err := id.CSR()
	if err != nil {
		t.Fatal(err)
	}
	status, body := postServedBootstrap(t, h, token, csr)
	if status != http.StatusOK {
		return id, status, body
	}
	var out struct {
		Certificate string `json:"certificate"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode bootstrap response: %v", err)
	}
	if err := id.UseCertificate([]byte(out.Certificate)); err != nil {
		t.Fatalf("adopt issued chain: %v", err)
	}
	return id, status, body
}

func TestAgentBootstrapRejectsRolePathWithoutConsumingToken(t *testing.T) {
	h := newRoleHarnessNamedWithEventOptions(t, "role-name-boundary-anchor",
		[]string{mtls.AgentRoleHost}, nil, nil, withIsolatedTenant)
	writer := seedScopedToken(t, h.store, h.tenant, "agents:write")
	token := mintServedEnrollmentToken(t, h.servedHarness, writer, "role-name-boundary", "")
	if _, code, body := v8Enroll(t, h.servedHarness, token, "host-a/role/network"); code != http.StatusBadRequest {
		t.Fatalf("forged role name = HTTP %d %s, want 400", code, body)
	}
	if _, code, body := v8Enroll(t, h.servedHarness, token, "host-a"); code != http.StatusOK {
		t.Fatalf("corrected agent name with the same token = HTTP %d %s, want 200", code, body)
	}
}

func TestCR015TokenPlanRejectsRolePathIdentityBeforeMint(t *testing.T) {
	h := newRoleHarnessNamedWithEventOptions(t, "cr015-token-plan-anchor",
		[]string{mtls.AgentRoleHost}, nil, nil, withIsolatedTenant)
	writer := seedScopedToken(t, h.store, h.tenant, "agents:write")
	for _, path := range []string{"/api/v1/agents/enrollment-tokens/preview", "/api/v1/agents/enrollment-tokens"} {
		status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, path, writer, "cr015-invalid-"+path,
			map[string]any{"allowed_identity": "host-a/role/network"})
		if status != http.StatusBadRequest {
			t.Errorf("%s accepted a token pinned to a role-forging identity: HTTP %d %s", path, status, body)
		}
	}
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/agents/enrollment-tokens", writer,
		"cr015-valid", map[string]any{"allowed_identity": "host-a"})
	if status != http.StatusCreated {
		t.Fatalf("valid agent identity refused after invalid plans: HTTP %d %s", status, body)
	}
}

func v8Dial(t *testing.T, h *roleHarness, id *mtls.AgentIdentity) *transport.AgentClient {
	t.Helper()
	creds, err := mtls.AgentClientCredentials(id, h.srv.AgentCACertPEM(), h.serverName, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(h.channelAddr, creds)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return transport.NewAgentClient(conn)
}

// V8-L1: every privileged role is forgeable through the CN with a host-only
// token; the forged role is invisible to the A191 grant mechanism in both
// directions: no grant is needed to get it, and an operator's grant that
// removes it is signed and reported applied while the certificate keeps it.
func TestV8L1ForgedRoleSurvivesRenewalAndOperatorRoleRemoval(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarnessNamedWithEventOptions(t, "v8-l1-anchor", []string{mtls.AgentRoleHost}, []string{"endpoint.verify"}, nil, withIsolatedTenant)
	// A principal holding agents:write and NOT agents:relay.grant (the built-in
	// cli role's position; here a scoped token, as a custom role would be).
	writer := seedScopedToken(t, h.store, h.tenant, "agents:write")

	// Control: the documented gate refuses this principal a token naming the role.
	st, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/agents/enrollment-tokens", writer, "v8-l1-control",
		map[string]any{"roles": []string{mtls.AgentRoleNetwork}})
	if st != http.StatusForbidden {
		t.Fatalf("control: an agents:write-only principal minted a network-role token directly (%d %s)", st, body)
	}
	t.Logf("control: agents:write asking for roles [network] = %d (the relay.grant gate works for the role list)", st)

	var forged []string
	var relay *mtls.AgentIdentity
	for _, role := range []string{mtls.AgentRoleNetwork, mtls.AgentRoleGateway, mtls.AgentRoleObserver, mtls.AgentRoleSessionObserver} {
		token := mintServedEnrollmentToken(t, h.servedHarness, writer, "v8-l1-"+role, "")
		id, st, body := v8Enroll(t, h.servedHarness, token, "v8-l1-"+role+"/role/"+role)
		if st != http.StatusOK {
			t.Logf("forged %s bootstrap refused (%d %s): the secure outcome", role, st, body)
			continue
		}
		t.Logf("host-only token + CN %q -> certificate roles %v", id.CommonName(), id.Roles())
		if slices.Contains(id.Roles(), role) {
			forged = append(forged, role)
		}
		if role == mtls.AgentRoleNetwork {
			relay = id
		}
	}
	// A token pinned to a role-forging name must be refused at mint, before the
	// operator can mistake the preview for a host-only plan.
	st, pinnedBody := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/agents/enrollment-tokens", writer,
		"v8-l1-pinned", map[string]any{"allowed_identity": "v8-l1-pinned/role/gateway"})
	if st != http.StatusBadRequest {
		t.Errorf("role-forging pinned identity was minted: HTTP %d %s", st, pinnedBody)
	}
	if len(forged) > 0 {
		t.Errorf("V8-L1: host-only tokens minted by an agents:write principal produced certificates carrying %v", forged)
	}
	if relay == nil {
		return
	}

	client := v8Dial(t, h, relay)
	if _, err := client.Heartbeat(ctx, &transport.HeartbeatRequest{Version: "v8", Status: "active"}); err != nil {
		t.Fatalf("forged relay heartbeat: %v", err)
	}
	reader := seedScopedToken(t, h.store, h.tenant, "agents:read")
	relayID := agentRowID(h.tenant, relay.CommonName())
	showAgent := func(label string) {
		t.Helper()
		st, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/agents", reader, nil)
		if st != http.StatusOK {
			t.Fatalf("list agents = %d %s", st, body)
		}
		var list struct {
			Agents []struct {
				ID         string          `json:"id"`
				Name       string          `json:"name"`
				Roles      []string        `json:"roles"`
				RoleSource string          `json:"role_source"`
				RoleGrant  json.RawMessage `json:"role_grant"`
			} `json:"agents"`
		}
		if err := json.Unmarshal(body, &list); err != nil {
			t.Fatal(err)
		}
		for _, a := range list.Agents {
			if a.ID == relayID {
				t.Logf("%s: GET /api/v1/agents shows %q roles=%v role_source=%s role_grant=%s", label, a.Name, a.Roles, a.RoleSource, a.RoleGrant)
			}
		}
	}
	showAgent("after enrollment")

	// The operator removes relay authority the documented way (A191).
	granter := seedScopedToken(t, h.store, h.tenant, "agents:relay.grant")
	st, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/agents/"+relayID+"/roles", granter, "v8-l1-remove",
		map[string]any{"roles": []string{mtls.AgentRoleHost}, "reason": "v8: remove relay authority"})
	if st != http.StatusOK {
		t.Fatalf("operator role removal = %d %s", st, body)
	}
	next, err := mtls.GenerateAgentKey(relay.CommonName())
	if err != nil {
		t.Fatal(err)
	}
	csr, err := next.CSR()
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := client.Renew(ctx, &transport.RenewRequest{CSRDER: csr})
	if err != nil {
		t.Fatalf("renewal: %v", err)
	}
	if err := next.UseCertificate(renewed.CertChainPEM); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(next.Roles(), mtls.AgentRoleNetwork) {
		t.Errorf("V8-L1: after the operator's grant of [host] was signed, the renewed certificate still reads %v: "+
			"a grant can neither add nor remove a role forged through the common name", next.Roles())
	}
	again := v8Dial(t, h, next)
	if _, err := again.Heartbeat(ctx, &transport.HeartbeatRequest{Version: "v8", Status: "active"}); err != nil {
		t.Fatalf("renewed heartbeat: %v", err)
	}
	showAgent("after the role-removal grant was signed")
	seedRoleJob(t, ctx, h, "endpoint.verify", "v8-l1-verify")
	claimed, err := again.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"endpoint.verify"}, Limit: 5, LeaseSeconds: 60})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed.Jobs) > 0 {
		t.Errorf("V8-L1: after the operator removed the role, the renewed certificate still claimed %d network-relay job(s)", len(claimed.Jobs))
	}
}
