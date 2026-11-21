// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"net/http"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// V8-L2: a network relay's claimed job requires the network capability at
// credential handoff, even when another certificate has the same agent name.
func TestCR016HostOnlyCloneCannotRedeemRelayCredential(t *testing.T) {
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
	if st != http.StatusConflict && st != http.StatusOK {
		t.Fatalf("second enrollment for the live relay = HTTP %d %s, want 409", st, body)
	}
	if st == http.StatusOK {
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
	// Model a certificate that a pre-fix build already issued to a same-name,
	// host-only clone. The CA signature is real. A host certificate can also
	// overlap a later network-role renewal, so credential handoff must enforce
	// the role even when both certificates have a recorded binding.
	legacy, err := mtls.GenerateAgentKey(relayName)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(legacy.Destroy)
	csr, err := legacy.CSR()
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := agentCertificateAuthorityURIs(ctx, h.store, h.log, h.tenant, nil)
	if err != nil {
		t.Fatal(err)
	}
	roles := append([]string{mtls.AgentRoleSPIFFEID(h.tenant, relayName, mtls.AgentRoleHost)}, bindings...)
	chain, err := crypto.SignAgentClientCSR(h.srv.agentCACertDER, h.srv.agentCASigner, csr,
		mtls.AgentSPIFFEID(h.tenant, relayName), roles, mtls.ClientCertTTL)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.UseCertificate(chain); err != nil {
		t.Fatal(err)
	}
	legacyClient := v8Dial(t, h, legacy)
	if _, err := legacyClient.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: jobID, Attempt: attempt}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a signed but unenrolled same-name certificate reached credential handoff: %v", err)
	}
	legacyLeaf, err := certinfo.Inspect(legacy.CertificateDER())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO agent_certificate_bindings
			(tenant_id, agent_id, serial, fingerprint, not_after, event_seq)
			VALUES ($1,$2,$3,$4,$5,1)`, h.tenant, agentRowID(h.tenant, relayName),
			legacyLeaf.SerialNumber, legacyLeaf.SHA256Fingerprint, legacyLeaf.NotAfter)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := legacyClient.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: jobID, Attempt: attempt}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("bound host-only clone crossed the redemption role gate: %v", err)
	}
	if _, err := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: jobID, Attempt: attempt}); err != nil {
		t.Fatalf("the real relay's own redemption was refused: %v", err)
	}
}
