// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"net/http"
	"slices"
	"testing"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// V8-L2: a network relay's claimed job requires the network capability at
// credential handoff, even when another certificate has the same agent name.
func TestV8L2HostOnlyCloneRedeemsTheRelaysClaimedApplianceCredential(t *testing.T) {
	ctx := context.Background()
	const relayName = "v8-l2-relay"
	h := newRoleHarnessNamedWithEventOptions(t, relayName, []string{mtls.AgentRoleNetwork}, []string{"connector.deploy"}, nil, withIsolatedTenant)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{Version: "v8", Status: "active"}); err != nil {
		t.Fatalf("relay heartbeat: %v", err)
	}
	jobID := seedSealedRelayJob(t, ctx, h)
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.deploy"}, Limit: 5, LeaseSeconds: 300})
	if err != nil || len(claimed.Jobs) != 1 || claimed.Jobs[0].JobID != jobID {
		t.Fatalf("relay claim = %+v, %v", claimed, err)
	}
	attempt := claimed.Jobs[0].Attempt

	writer := seedScopedToken(t, h.store, h.tenant, "agents:write")
	token := mintServedEnrollmentToken(t, h.servedHarness, writer, "v8-l2-relay-clone", "")
	clone, st, body := v8Enroll(t, h.servedHarness, token, relayName)
	if st != http.StatusOK {
		t.Logf("second enrollment for the live relay refused (%d %s): the secure outcome", st, body)
	} else {
		if slices.Contains(clone.Roles(), mtls.AgentRoleNetwork) {
			t.Fatalf("premise: the clone should be host-only, got %v", clone.Roles())
		}
		cloneClient := v8Dial(t, h, clone)
		redeemed, err := cloneClient.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: jobID, Attempt: attempt})
		if err == nil {
			var names []string
			for _, item := range redeemed.Items {
				if len(item.Value) > 0 {
					names = append(names, item.Name)
				}
			}
			slices.Sort(names)
			t.Errorf("a host-only clone (roles %v) redeemed the relay's claimed appliance credential items %v", clone.Roles(), names)
		}
	}
	if _, err := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: jobID, Attempt: attempt}); err != nil {
		t.Fatalf("the real relay's own redemption was refused: %v", err)
	}
}
