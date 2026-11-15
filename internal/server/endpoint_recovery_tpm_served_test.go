// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/deviceattesttest"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// TestServedReplacementPreviewListsTheNginxReexecForATPMHeldKeyTPMO1L3L1:
// after containment stopped an nginx listener, the replacement preview lists
// the actions the replacement deploy will run. Under a profile that requires
// TPM-held host keys those are nginx -t and the host profile's nginx-upgrade
// (TPM-O1-L3), so a recovery action pinned to nginx-upgrade is one a
// replacement runs; the same target under a profile without the requirement
// lists nginx alone.
func TestServedReplacementPreviewListsTheNginxReexecForATPMHeldKeyTPMO1L3L1(t *testing.T) {
	hostTPM, err := deviceattesttest.NewTPMIdentity(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		tpm     bool
		actions []string
	}{
		{"a TPM-held key", true, []string{"nginx", "nginx-upgrade"}},
		{"a software key", false, []string{"nginx"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, []string{"connector.deploy", "endpoint.renew", relay.KindEndpointContain},
				func(d *Deps) { d.DefaultProfile = "tpm-o1-l3-l1" })
			token := seedScopedToken(t, h.store, h.tenant, "connectors:write", "connectors:read", "owners:read", "profiles:write",
				"identities:read", "identities:write", "certs:read", "certs:issue", "lifecycle:read")
			spec := map[string]any{"max_validity": "12m", "allowed_protocols": []string{"api"}}
			if tc.tpm {
				spec["host_key_attestation"] = map[string]any{"required": true, "format": "tpm", "attestation_roots_pem": []string{string(hostTPM.RootPEM())}}
			}
			if code, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/profiles", token, map[string]any{"name": "tpm-o1-l3-l1", "spec": spec}); code != http.StatusCreated {
				t.Fatalf("profile: HTTP %d %s", code, body)
			}
			agentID := agentRowID(h.tenant, h.agent)
			if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "test-1.0", Status: "active"}); err != nil {
				t.Fatalf("heartbeat: %v", err)
			}
			f := seedPurgeFixture(t, ctx, h, token, agentID)
			original, err := h.store.GetIdentity(ctx, h.tenant, f.identityID)
			if err != nil {
				t.Fatal(err)
			}
			original.Status = "deployed"
			original.Attributes = json.RawMessage(`{"deployment_target_id":"` + f.targetID + `"}`)
			if err := h.store.UpsertIdentity(ctx, original); err != nil {
				t.Fatal(err)
			}
			status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/connectors/targets/"+f.targetID+"/contain/preview", token, nil)
			if status != http.StatusOK {
				t.Fatalf("containment preview = %d %s", status, body)
			}
			var plan map[string]any
			if err := json.Unmarshal(body, &plan); err != nil {
				t.Fatal(err)
			}
			status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/connectors/targets/"+f.targetID+"/contain", token, "tpm-o1-l3-l1-contain", map[string]any{
				"target_revision": plan["target_revision"], "identity_id": plan["identity_id"],
				"expected_fingerprint": plan["expected_fingerprint"], "required_agent_id": plan["required_agent_id"],
				"preview_fingerprint": plan["preview_fingerprint"], "reason": "key compromise",
			})
			if status != http.StatusAccepted {
				t.Fatalf("contain = %d %s", status, body)
			}
			claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindEndpointContain}, Limit: 1, LeaseSeconds: 60})
			if err != nil || len(claimed.Jobs) != 1 {
				t.Fatalf("claim containment = %+v err=%v", claimed, err)
			}
			var contain relay.ContainmentIntent
			if err := json.Unmarshal(claimed.Jobs[0].Payload, &contain); err != nil {
				t.Fatal(err)
			}
			before := transport.ProbeTranscript{Address: "127.0.0.1:8443", Vantage: transport.VantageLocal, Reached: true,
				ExpectedFingerprint: f.fingerprint, ObservedFingerprint: f.fingerprint, ObservedAtUnix: time.Now().Unix()}
			gone := transport.ProbeTranscript{Address: "127.0.0.1:8443", Vantage: transport.VantageLocal,
				ExpectedFingerprint: f.fingerprint, Error: "connection refused", ObservedAtUnix: time.Now().Unix()}
			stopped := relay.ContainmentReport{TargetID: contain.TargetID, TargetRevision: contain.TargetRevision,
				IdentityID: contain.IdentityID, ExpectedFingerprint: contain.ExpectedFingerprint, Action: "stop-tpm-o1-l3-l1",
				State: relay.ContainmentStopped, Before: before, After: []transport.ProbeTranscript{gone, gone}}
			reportRecoveryJob(t, h, claimed.Jobs[0], stopped, stopped.Digest())

			status, body = secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings/preview", token, map[string]any{
				"replace_identity_id": f.identityID, "owner_id": original.OwnerID, "identity_name": original.Name,
				"target_id": f.targetID, "issuer": map[string]any{"source": "platform", "id": "trstctl-issuing-ca"},
				"reason": "replace the contained certificate",
			})
			if status != http.StatusOK {
				t.Fatalf("replacement preview = %d %s", status, body)
			}
			var preview struct {
				RecoveryReadiness *struct {
					DeployActions []string `json:"deploy_actions"`
				} `json:"recovery_readiness"`
			}
			if err := json.Unmarshal(body, &preview); err != nil || preview.RecoveryReadiness == nil {
				t.Fatalf("replacement preview without recovery readiness: %s err=%v", body, err)
			}
			if !slices.Equal(preview.RecoveryReadiness.DeployActions, tc.actions) {
				t.Fatalf("deploy actions = %v, want %v", preview.RecoveryReadiness.DeployActions, tc.actions)
			}
		})
	}
}
