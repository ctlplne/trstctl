// SPDX-License-Identifier: BUSL-1.1

package server

// V8 verification of S9's enrollment and agent-channel leads (fresh verifier).
// Not product code; never committed. Each test asserts the secure behaviour and
// fails on the pinned code because of the defect it names. Self-contained: it
// does not need the reader's s9_review_repro_test.go.

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/store"
)

// V8-L2 (deterministic impact): a second enrollment under a live host's name
// is the same agent to every lease check, so the clone claims the victim's
// host-pinned deploy and redeems the control plane's private key for it.
func TestV8L2CloneOfALiveHostRedeemsItsPinnedDeployKey(t *testing.T) {
	ctx := context.Background()
	const victim = "v8-l2-host"
	h := newRoleHarnessNamedWithEventOptions(t, victim, []string{mtls.AgentRoleHost}, []string{"connector.deploy"}, nil, withIsolatedTenant)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{Version: "v8", Status: "active"}); err != nil {
		t.Fatalf("victim heartbeat: %v", err)
	}
	victimID := agentRowID(h.tenant, victim)

	// A host deployment target assigned to the victim, and the sealed deploy
	// for it (certificate + the control plane's private key), pinned to it.
	root := t.TempDir()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	targetConfig, err := json.Marshal(map[string]any{
		"cert_path": filepath.Join(root, "site.crt"), "key_path": filepath.Join(root, "site.key"),
		"verify_address": ln.Addr().String(), "verify_server_name": "v8-victim.test",
		"required_agent_id": victimID,
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{
		Name: "v8-victim-site", Type: "nginx", Config: targetConfig, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := issueHostPair(t, h, "v8-victim.test")
	defer secret.Wipe(certPEM)
	defer secret.Wipe(keyPEM)
	leafDER, err := certinfo.LeafDER(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.RecordCertificate(ctx, h.tenant, store.Certificate{Fingerprint: connector.CertificateFingerprint(certPEM),
		CertificateDER: leafDER, CertificatePEM: certPEM, Source: "import"}); err != nil {
		t.Fatal(err)
	}
	const idemKey = "v8-l2-host-deploy"
	raw, err := json.Marshal(connector.DeployPayload{
		Connector: "nginx", Target: "v8-victim-site", TargetID: target.ID, TargetRevision: target.RevisionID,
		TargetConfig: targetConfig, CertPEM: certPEM, KeyPEM: keyPEM, Fingerprint: connector.CertificateFingerprint(certPEM),
	})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := h.srv.sealRelayDeployForTest(ctx, h.tenant, "connector.deploy", idemKey, raw)
	secret.Wipe(raw)
	if err != nil {
		t.Fatal(err)
	}
	var jobID int64
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, required_agent_role, required_agent_id)
			 VALUES ($1, 'connector.deploy', $2, $3, 'host', $4) RETURNING id`,
			h.tenant, sealed, idemKey, victimID).Scan(&jobID)
	}); err != nil {
		t.Fatal(err)
	}

	// An agents:write principal mints a token pinned to the LIVE victim's name.
	writer := seedScopedToken(t, h.store, h.tenant, "agents:write")
	token := mintServedEnrollmentToken(t, h.servedHarness, writer, "v8-l2-clone", victim)
	clone, st, body := v8Enroll(t, h.servedHarness, token, victim)
	if st != http.StatusOK {
		t.Logf("second enrollment for the live host refused (%d %s): the secure outcome", st, body)
		return
	}
	t.Errorf("V8-L2: a second certificate (roles %v) was issued for the live, heartbeating host %q", clone.Roles(), victim)
	cloneClient := v8Dial(t, h, clone)
	claimed, err := cloneClient.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{"connector.deploy"}, Limit: 5, LeaseSeconds: 120})
	if err != nil {
		t.Fatalf("clone claim: %v", err)
	}
	attempt := 0
	for _, job := range claimed.Jobs {
		if job.JobID == jobID {
			attempt = job.Attempt
		}
	}
	if attempt == 0 {
		t.Logf("the clone was not handed the victim's pinned job: %+v", claimed.Jobs)
		return
	}
	t.Errorf("V8-L2: the clone claimed the victim's host-pinned deploy (job %d, required_agent_id %s)", jobID, victimID)
	redeemed, err := cloneClient.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: jobID, Attempt: attempt})
	if err != nil {
		t.Logf("clone redemption refused: %v", err)
		return
	}
	for _, item := range redeemed.Items {
		if item.Name == "credential.key_pem" && bytes.Equal(item.Value, keyPEM) {
			t.Errorf("V8-L2: the clone redeemed the victim host's deployment private key (credential.key_pem, %d bytes)", len(item.Value))
		}
	}
}

// V8-L3: on an already-open connection an expired certificate is not only
// served, it renews itself into a fresh certificate.
func TestV8L3ExpiredCertificateRenewsItselfOnAnOpenConnection(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarnessNamedWithEventOptions(t, "v8-l3-anchor", []string{mtls.AgentRoleHost}, nil, nil, withIsolatedTenant)
	const cn = "v8-l3-short-lived"
	id, err := mtls.GenerateAgentKey(cn)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := id.CSR()
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := agentCertificateAuthorityURIs(ctx, h.store, h.log, h.tenant, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The served CA and signer; only the lifetime is shortened (24 h is a constant).
	chain, err := crypto.SignAgentClientCSR(h.srv.agentCACertDER, h.srv.agentCASigner, csr, mtls.AgentSPIFFEID(h.tenant, cn), bindings, 4*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := id.UseCertificate(chain); err != nil {
		t.Fatal(err)
	}
	client := v8Dial(t, h, id)
	if _, err := client.Heartbeat(ctx, &transport.HeartbeatRequest{Version: "v8", Status: "active"}); err != nil {
		t.Fatalf("heartbeat while valid: %v", err)
	}
	time.Sleep(time.Until(id.NotAfter()) + 1500*time.Millisecond)

	fresh := v8Dial(t, h, id)
	freshCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := fresh.Heartbeat(freshCtx, &transport.HeartbeatRequest{Version: "v8", Status: "active"}); err == nil {
		t.Fatal("premise: a NEW connection accepted the expired certificate")
	}
	next, err := mtls.GenerateAgentKey(cn)
	if err != nil {
		t.Fatal(err)
	}
	nextCSR, err := next.CSR()
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := client.Renew(ctx, &transport.RenewRequest{CSRDER: nextCSR})
	if err != nil {
		t.Logf("renewal with the expired certificate refused: %v (the secure outcome)", err)
		return
	}
	if err := next.UseCertificate(renewed.CertChainPEM); err != nil {
		t.Fatal(err)
	}
	t.Errorf("V8-L3: a certificate that expired at %s renewed itself on the open connection into one valid until %s",
		id.NotAfter().UTC().Format(time.RFC3339), next.NotAfter().UTC().Format(time.RFC3339))
}
