// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/store"
)

func TestHostManagementReferencesRequireReviewedTargetAuthority(t *testing.T) {
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, agentJobKindEndpointRenew)
	ctx := t.Context()
	agentID := registeredRoleAgentID(t, h)
	config := json.RawMessage(`{"executor":"agent","required_agent_id":"` + agentID + `","keystore_password_ref":"secret://reviewed-password"}`)
	target, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{Name: "reviewed-java", Type: "java-keystore", Config: config, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := h.srv.sealTenantSecretForTest(ctx, h.tenant, "reviewed-password", []byte(canaryPassword))
	if err != nil {
		t.Fatal(err)
	}
	seedApplicationSecretFixture(t, h.store, h.tenant, "reviewed-password", sealed)
	svc, ok := h.srv.agentServiceForTest()
	if !ok {
		t.Fatal("missing agent service")
	}
	for _, tc := range []struct {
		name        string
		edit        func(*RelayDeployIntent)
		otherTenant bool
		wantOK      bool
	}{
		{name: "legacy omitted reference list", wantOK: true},
		{name: "explicit reference", edit: func(i *RelayDeployIntent) { i.CredentialRefs = []string{"secret://reviewed-password"} }, wantOK: true},
		{name: "unrelated subject reference is not redeemed", edit: func(i *RelayDeployIntent) { i.SubjectCommonName = "secret://unrelated" }, wantOK: true},
		{name: "missing revision", edit: func(i *RelayDeployIntent) { i.Revision = "" }},
		{name: "unknown revision", edit: func(i *RelayDeployIntent) { i.Revision = "missing" }},
		{name: "changed config", edit: func(i *RelayDeployIntent) {
			i.TargetConfig = bytes.ReplaceAll(config, []byte("reviewed-password"), []byte("unrelated"))
		}},
		{name: "changed reference list", edit: func(i *RelayDeployIntent) { i.CredentialRefs = []string{"secret://unrelated"} }},
		{name: "changed connector", edit: func(i *RelayDeployIntent) { i.Connector = "nginx" }},
		{name: "other tenant", otherTenant: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			intent := RelayDeployIntent{Connector: target.Type, TargetID: target.ID, Revision: target.RevisionID, TargetConfig: config}
			if tc.edit != nil {
				tc.edit(&intent)
			}
			payload, err := json.Marshal(intent)
			if err != nil {
				t.Fatal(err)
			}
			tenantID := h.tenant
			if tc.otherTenant {
				tenantID = uuid.NewString()
			}
			material, err := svc.relayCredentials.resolveJobCredential(ctx, tenantID, store.AgentJobForRedemption{Destination: agentJobKindEndpointRenew, RequiredAgentID: agentID, Payload: payload})
			if (err == nil) != tc.wantOK {
				t.Fatalf("success=%v err=%v", err == nil, err)
			}
			if material.wipe != nil {
				defer material.wipe()
			}
			if err == nil && (len(material.items) != 1 || material.items[0].Name != "secret://reviewed-password" || !bytes.Equal(material.items[0].Value, []byte(canaryPassword))) {
				t.Fatal("wrong management material")
			}
		})
	}
	// Existing queued bytes are never rewritten when a host claims the names.
	legacy, _ := json.Marshal(RelayDeployIntent{Connector: target.Type, TargetID: target.ID, Revision: target.RevisionID, TargetConfig: config})
	original := append([]byte(nil), legacy...)
	projected, err := svc.projectClaimedJobPayload(store.AgentJob{Destination: agentJobKindEndpointRenew, Payload: legacy})
	var intent RelayDeployIntent
	if err != nil || json.Unmarshal(projected, &intent) != nil || len(intent.CredentialRefs) != 1 || !bytes.Equal(original, legacy) {
		t.Fatal("legacy projection lost authority or changed queued bytes")
	}
	for _, mode := range []string{"disabled", "reassigned"} {
		t.Run(mode, func(t *testing.T) {
			changed := target
			changed.EnabledSet = true
			if mode == "disabled" {
				changed.Enabled = false
			} else {
				changed.Config = bytes.ReplaceAll(config, []byte(agentID), []byte(uuid.NewString()))
			}
			if err := h.store.UpsertDeploymentTarget(ctx, changed); err != nil {
				t.Fatal(err)
			}
			material, err := svc.relayCredentials.resolveJobCredential(ctx, h.tenant, store.AgentJobForRedemption{Destination: agentJobKindEndpointRenew, RequiredAgentID: agentID, Payload: legacy})
			if material.wipe != nil {
				material.wipe()
			}
			if err == nil {
				t.Fatal("changed host authority redeemed management secret")
			}
		})
	}
}

func TestServedHostManagementResolutionFailureDoesNotConsumeAttempt(t *testing.T) {
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, agentJobKindEndpointRenew)
	ctx := t.Context()
	agentID := registeredRoleAgentID(t, h)
	config := json.RawMessage(`{"executor":"agent","required_agent_id":"` + agentID + `","keystore_password_ref":"secret://initially-unavailable"}`)
	target, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{Name: "java", Type: "java-keystore", Config: config, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(RelayDeployIntent{Connector: target.Type, TargetID: target.ID, Revision: target.RevisionID, TargetConfig: config})
	var jobID int64
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO outbox(tenant_id,destination,payload,idempotency_key,required_agent_id,required_agent_role) VALUES($1,'endpoint.renew',$2,'host-management-retry',$3,'host') RETURNING id`, h.tenant, payload, agentID).Scan(&jobID)
	}); err != nil {
		t.Fatal(err)
	}
	req := &transport.RedeemJobCredentialRequest{JobID: jobID, Attempt: 1}
	if _, err := h.client.RedeemJobCredential(ctx, req); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unclaimed request: %v", err)
	}
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{agentJobKindEndpointRenew}, Limit: 1, LeaseSeconds: 120})
	if err != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("claim: %v", err)
	}
	req.Attempt = claimed.Jobs[0].Attempt
	if _, err := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: jobID, Attempt: req.Attempt + 1}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("wrong attempt: %v", err)
	}
	if result, err := h.client.RedeemJobCredential(ctx, req); status.Code(err) != codes.Unavailable || result != nil {
		t.Fatalf("missing secret: %v", err)
	}
	sealed, err := h.srv.sealTenantSecretForTest(ctx, h.tenant, "initially-unavailable", []byte(canaryPassword))
	if err != nil {
		t.Fatal(err)
	}
	seedApplicationSecretFixture(t, h.store, h.tenant, "initially-unavailable", sealed)
	result, err := h.client.RedeemJobCredential(ctx, req)
	if err != nil || len(result.Items) != 1 || result.Items[0].Name != "secret://initially-unavailable" || !bytes.Equal(result.Items[0].Value, []byte(canaryPassword)) {
		t.Fatalf("same attempt could not recover: %v", err)
	}
	for _, item := range result.Items {
		secret.Wipe(item.Value)
	}
	if _, err := h.client.RedeemJobCredential(ctx, req); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("replay: %v", err)
	}
}
