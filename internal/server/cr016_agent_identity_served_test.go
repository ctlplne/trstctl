// SPDX-License-Identifier: BUSL-1.1

package server

// CR-016: a second enrollment must not claim a live host's pinned deployment
// and redeem its private key, even if the second caller knows the host name.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// V8-L2 (deterministic impact): a second enrollment under a live host's name
// is the same agent to every lease check, so the clone claims the victim's
// host-pinned deploy and redeems the control plane's private key for it.
func TestCR016DuplicateNameDeniedBeforeFirstHeartbeat(t *testing.T) {
	const name = "cr016-before-heartbeat"
	h := newRoleHarnessNamedWithEventOptions(t, name, []string{mtls.AgentRoleHost}, nil, nil, withIsolatedTenant)
	writer := seedScopedToken(t, h.store, h.tenant, "agents:write")
	token := mintServedEnrollmentToken(t, h.servedHarness, writer, "cr016-before-heartbeat-clone", name)
	if _, code, body := v8Enroll(t, h.servedHarness, token, name); code != http.StatusConflict {
		t.Fatalf("second enrollment before first heartbeat = HTTP %d %s, want 409", code, body)
	}
}

func TestCR016ConcurrentBootstrapAdmitsOneCertificate(t *testing.T) {
	const name = "cr016-concurrent-bootstrap"
	h := newRoleHarnessNamedWithEventOptions(t, "cr016-concurrent-fixture", []string{mtls.AgentRoleHost}, nil, nil, withIsolatedTenant)
	writer := seedScopedToken(t, h.store, h.tenant, "agents:write")
	tokens := []string{
		mintServedEnrollmentToken(t, h.servedHarness, writer, "cr016-concurrent-one", name),
		mintServedEnrollmentToken(t, h.servedHarness, writer, "cr016-concurrent-two", name),
	}
	csrs := make([][]byte, 2)
	for i := range csrs {
		identity, err := mtls.GenerateAgentKey(name)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(identity.Destroy)
		csrs[i], err = identity.CSR()
		if err != nil {
			t.Fatal(err)
		}
	}
	type result struct {
		code int
		err  error
	}
	results := make(chan result, 2)
	for i := range tokens {
		go func(i int) {
			wire, err := json.Marshal(map[string]string{"token": tokens[i], "csr": base64.StdEncoding.EncodeToString(csrs[i])})
			if err != nil {
				results <- result{err: err}
				return
			}
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
				h.ts.URL+"/enroll/bootstrap", bytes.NewReader(wire))
			if err != nil {
				results <- result{err: err}
				return
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := h.ts.Client().Do(req)
			if err != nil {
				results <- result{err: err}
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			results <- result{code: resp.StatusCode}
		}(i)
	}
	var success, refused int
	for range 2 {
		out := <-results
		if out.err != nil {
			t.Fatal(out.err)
		}
		switch out.code {
		case http.StatusOK:
			success++
		case http.StatusConflict:
			refused++
		default:
			t.Fatalf("concurrent bootstrap returned HTTP %d, want 200 or 409", out.code)
		}
	}
	if success != 1 || refused != 1 {
		t.Fatalf("concurrent bootstrap: %d issued, %d refused; want one of each", success, refused)
	}
	count := 0
	if err := h.log.Replay(context.Background(), 0, func(e events.Event) error {
		if e.Type != projections.EventAgentCertEnrolled || e.TenantID != h.tenant {
			return nil
		}
		var enrolled projections.AgentCertEnrolled
		if err := json.Unmarshal(e.Data, &enrolled); err != nil {
			return err
		}
		if enrolled.Agent == name {
			count++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("concurrent bootstrap wrote %d source enrollment events, want one", count)
	}
}

// The event append can succeed before its read-model projection. A retry with
// another token must recover the first certificate's binding from the event ID,
// not issue a second certificate while the projection is absent.
func TestCR016LostEnrollmentProjectionDoesNotAdmitClone(t *testing.T) {
	const name = "cr016-lost-projection"
	h := newRoleHarnessNamedWithEventOptions(t, name, []string{mtls.AgentRoleHost}, nil, nil, withIsolatedTenant)
	agentID := agentRowID(h.tenant, name)
	if err := h.store.WithTenant(context.Background(), h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(),
			`DELETE FROM agent_certificate_bindings WHERE tenant_id=$1 AND agent_id=$2`, h.tenant, agentID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	writer := seedScopedToken(t, h.store, h.tenant, "agents:write")
	token := mintServedEnrollmentToken(t, h.servedHarness, writer, "cr016-projection-clone", name)
	if _, code, body := v8Enroll(t, h.servedHarness, token, name); code != http.StatusConflict {
		t.Fatalf("second certificate after lost projection = HTTP %d %s, want 409", code, body)
	}
	original, err := certinfo.Inspect(h.identity.Identity().CertificateDER())
	if err != nil {
		t.Fatal(err)
	}
	bound, matches, err := h.store.AgentCertificateMatches(context.Background(), h.tenant, agentID,
		original.SerialNumber, original.SHA256Fingerprint)
	if err != nil || !bound || !matches {
		t.Fatalf("first certificate binding was not recovered from its event: bound=%v matches=%v err=%v", bound, matches, err)
	}
}

func TestCR016LegacyHeartbeatPinsExistingCertificateBeforeSecretWork(t *testing.T) {
	ctx := context.Background()
	const name = "cr016-legacy-heartbeat"
	h := newRoleHarnessNamedWithEventOptions(t, "cr016-legacy-fixture", []string{mtls.AgentRoleHost}, nil, nil, withIsolatedTenant)
	legacy := cr016SignHistoricalAgent(t, h, name)
	legacyLeaf, err := certinfo.Inspect(legacy.CertificateDER())
	if err != nil {
		t.Fatal(err)
	}
	// An older build wrote this heartbeat and agent row but no enrollment
	// binding event. Keep the history faithful instead of deleting a new event.
	wire, err := json.Marshal(projections.AgentHeartbeat{ID: agentRowID(h.tenant, name), Agent: name,
		Version: "legacy", Status: "active", CertSerial: legacyLeaf.SerialNumber, Roles: []string{mtls.AgentRoleHost}})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := h.log.Append(ctx, events.Event{Type: projections.EventAgentHeartbeat, TenantID: h.tenant, SchemaVersion: 1, Data: wire})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(h.store).Apply(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if _, err := v8Dial(t, h, legacy).Heartbeat(ctx, &transport.HeartbeatRequest{Version: "legacy", Status: "active"}); err != nil {
		t.Fatalf("historically heartbeating certificate could not recover its binding: %v", err)
	}
	if !h.hasEvent(t, projections.EventAgentCertLegacyBound) {
		t.Fatal("legacy certificate was accepted without an immutable binding event")
	}
	clone := cr016SignHistoricalAgent(t, h, name)
	if _, err := v8Dial(t, h, clone).Heartbeat(ctx, &transport.HeartbeatRequest{Version: "clone", Status: "active"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("historical same-name clone reached the agent channel: %v", err)
	}
}

func cr016SignHistoricalAgent(t *testing.T, h *roleHarness, name string) *mtls.AgentIdentity {
	t.Helper()
	clone, err := mtls.GenerateAgentKey(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clone.Destroy)
	csr, err := clone.CSR()
	if err != nil {
		t.Fatal(err)
	}
	registration, err := agentCertificateAuthorityURIs(context.Background(), h.store, h.log, h.tenant, nil)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := crypto.SignAgentClientCSR(h.srv.agentCACertDER, h.srv.agentCASigner, csr,
		mtls.AgentSPIFFEID(h.tenant, name), append([]string{mtls.AgentRoleSPIFFEID(h.tenant, name, mtls.AgentRoleHost)}, registration...), mtls.ClientCertTTL)
	if err != nil {
		t.Fatal(err)
	}
	if err := clone.UseCertificate(chain); err != nil {
		t.Fatal(err)
	}
	return clone
}

func TestCR016CloneOfALiveHostCannotRedeemPinnedDeployKey(t *testing.T) {
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
	if st == http.StatusConflict {
		return
	}
	if st != http.StatusOK {
		t.Fatalf("second enrollment for the live host = HTTP %d %s, want 409", st, body)
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
