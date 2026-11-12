// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentrelay "trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/digicert"
	"trstctl.com/trstctl/internal/ca/digicert/digicertfake"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// issueOnlyCA is an external CA whose integration issues but cannot revoke by
// serial or from the certificate (registered as a kind that cannot).
type issueOnlyCA struct{ ca.CA }

// P3-L2: a planned switch away from a vendor CA. The endpoint serves a leaf a
// DigiCert stand-in issued; the switch moves it to a trstctl root, and once
// the endpoint serves the new chain the predecessor is revoked (superseded)
// at the vendor that issued it. The vendor holds the request for approval
// first: the revocation is neither recorded nor the member's verdict given
// until the vendor accepts it. A member whose vendor integration cannot
// revoke is refused at start and named in the assessment.
func TestServedPlannedSwitchRevokesAVendorPredecessorAtTheVendorP3L2(t *testing.T) {
	ctx := context.Background()
	dc, err := digicertfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dc.Close)
	vendor := digicert.New("digicert", dc.URL(), []byte(dc.APIKey()), digicert.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))
	const vendorID, issueOnlyID = "p3l2-digicert", "p3l2-issue-only"
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost},
		[]string{agentrelay.KindTrustDistribute, agentrelay.KindEndpointRenew, agentrelay.KindConnectorRollback},
		func(d *Deps) {
			d.DefaultProfile = "p3l2-api"
			d.ExternalCAs = append(d.ExternalCAs,
				ExternalCA{ID: vendorID, Type: "digicert", Name: "DigiCert (stand-in)", CA: vendor},
				ExternalCA{ID: issueOnlyID, Type: "venafi", Name: "Issue-only vendor (stand-in)", CA: issueOnlyCA{vendor}})
		})
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "p3l2-test", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	fixture, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fixture.Close() })
	certPath, keyPath := filepath.Join(root, "listener.crt"), filepath.Join(root, "listener.key")
	trustPath := filepath.Join(root, "next-root.pem")
	const dnsName, issueOnlyName = "vendor-switch-p3l2.test", "issue-only-p3l2.test"

	// The predecessor: a leaf the vendor issued for a key the endpoint holds.
	vendorLeaf := func(name string) (ca.Certificate, []byte) {
		t.Helper()
		key, err := crypto.GenerateHostSubjectKey(name, []string{name})
		if err != nil {
			t.Fatal(err)
		}
		defer key.Destroy()
		issued, err := vendor.Issue(ctx, ca.IssueRequest{TenantID: h.tenant, CSR: key.CSRDER, DNSNames: []string{name}, TTL: 24 * time.Hour})
		if err != nil {
			t.Fatalf("the vendor issues %s: %v", name, err)
		}
		keyPEM, err := key.PrivateKeyPEM()
		if err != nil {
			t.Fatal(err)
		}
		return issued, keyPEM
	}
	issued, keyPEM := vendorLeaf(dnsName)
	if err := fixture.WriteFile("listener.crt", issued.CertificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fixture.WriteFile("listener.key", keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	secret.Wipe(keyPEM)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	tlsServer, err := mtls.ServerCertFromFiles(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer.SetReloadCheckInterval(time.Millisecond)
	httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})} // #nosec G112 -- loopback fixture closed below (CWE-400)
	serveDone := make(chan error, 1)
	go func() { serveDone <- tlsServer.ServeHTTPS(httpServer, listener) }()
	t.Cleanup(func() {
		_ = httpServer.Close()
		if serveErr := <-serveDone; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			t.Errorf("p3l2 listener: %v", serveErr)
		}
	})

	spec, err := json.Marshal(map[string]any{"name": "p3l2-api", "max_validity": "720h", "allowed_protocols": []string{"api"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.CreateProfile(ctx, h.tenant, "p3l2-api", spec); err != nil {
		t.Fatal(err)
	}
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "workload", "P3-L2 owner", "")
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := h.srv.obHandler.(*issuanceDispatcher)
	recorder := &issuanceDispatcherHarness{store: h.store, log: h.log, orch: h.srv.orch, outbox: h.srv.outbox, handler: dispatcher, tenant: h.tenant}
	// deployedFrom makes an identity deployed to a host target whose last
	// delivery is a leaf the external registry issued, as the registry
	// records it.
	deployedFrom := func(name, authorityID, verifyAddress, certFile, keyFile string, issued ca.Certificate) (string, store.Certificate) {
		t.Helper()
		cfg, err := json.Marshal(map[string]any{
			"executor": "agent", "cert_path": certFile, "key_path": keyFile,
			"required_agent_id": agentRowID(h.tenant, h.agent), "required_agent_role": mtls.AgentRoleHost,
			"verify_address": verifyAddress, "verify_server_name": name,
		})
		if err != nil {
			t.Fatal(err)
		}
		target, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{Name: "host/" + name, Type: "nginx", Config: cfg, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		attrs, err := json.Marshal(map[string]string{"deployment_target_id": target.ID, "connector": target.Type, "target": target.Name, "profile_name": "p3l2-api"})
		if err != nil {
			t.Fatal(err)
		}
		ident, err := h.srv.orch.CreateIdentity(ctx, h.tenant, store.Identity{Kind: store.KindX509Certificate, Name: name, OwnerID: owner.ID, Attributes: attrs})
		if err != nil {
			t.Fatal(err)
		}
		ident.Status = string(orchestrator.StateDeployed)
		if err := h.store.UpsertIdentity(ctx, ident); err != nil {
			t.Fatal(err)
		}
		leaf := recordVendorIssuedLeaf(t, recorder, authorityID, owner.ID, issued)
		identityID := ident.ID
		if _, err := h.srv.orch.RecordConnectorDelivery(ctx, h.tenant, store.ConnectorDeliveryReceipt{
			IdentityID: &identityID, Destination: "connector.deploy", Connector: target.Type, Target: target.Name,
			Fingerprint: leaf.Fingerprint, Status: "delivered", Reason: "p3l2 fixture", IdempotencyKey: "p3l2-deploy-" + name,
		}); err != nil {
			t.Fatal(err)
		}
		return ident.ID, leaf
	}
	identityID, old := deployedFrom(dnsName, vendorID, address, certPath, keyPath, issued)
	if old.IssuingExternalCAID != vendorID {
		t.Fatalf("the predecessor's issuer = %q, want the vendor", old.IssuingExternalCAID)
	}
	issueOnlyLeaf, _ := vendorLeaf(issueOnlyName)
	issueOnlyIdentity, _ := deployedFrom(issueOnlyName, issueOnlyID, "127.0.0.1:1",
		filepath.Join(root, "issue-only.crt"), filepath.Join(root, "issue-only.key"), issueOnlyLeaf)

	caOperator := seedScopedTokenSubject(t, h.store, h.tenant, "p3l2-ca-operator", "issuers:read", "issuers:write")
	caApprover := seedScopedTokenSubject(t, h.store, h.tenant, "p3l2-ca-custodian", "issuers:read", "issuers:write")
	rootSpec := map[string]any{
		"common_name": "P3-L2 new root", "max_path_len": 1, "ttl_seconds": int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{dnsName, issueOnlyName}, "extended_key_usages": []string{"serverAuth"}, "signature_algorithm": "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h.servedHarness, caOperator, "create_root", "", rootSpec, 1, "p3l2-root-ceremony")
	approveCACeremony(t, h.servedHarness, caApprover, ceremony.ID, 1, "p3l2-root-approval")
	newRoot := createRootCA(t, h.servedHarness, caOperator, ceremony.ID, rootSpec, "p3l2-root-create")

	// The assessment names the vendor that would revoke each predecessor,
	// and blocks the member whose vendor cannot.
	assessor := seedScopedTokenSubject(t, h.store, h.tenant, "p3l2-assessor", "graph:read")
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/migrations/assess", assessor, "p3l2-assess", map[string]any{
		"plan_id": "switch-p3l2", "require_full_trust": true, "revoke_predecessors": true,
		"waves": []any{map[string]any{"id": "canary", "ordinal": 1, "members": []any{identityID, issueOnlyIdentity}}},
	})
	var assessed migration.Assessment
	if status != http.StatusOK || json.Unmarshal(body, &assessed) != nil || len(assessed.Predecessors) != 2 {
		t.Fatalf("assess the switch: HTTP %d %s", status, body)
	}
	if p := assessed.Predecessors[0]; p.Member != identityID || p.ExternalCAID != vendorID || p.CAID != "" ||
		p.CAName != "DigiCert (stand-in)" || p.Serial != old.Serial || !p.Revocable {
		t.Fatalf("the vendor predecessor's assessment = %+v", p)
	}
	if p := assessed.Predecessors[1]; p.Member != issueOnlyIdentity || p.Revocable || !strings.Contains(p.Problem, "cannot revoke") {
		t.Fatalf("the issue-only vendor's predecessor = %+v; want it not revocable", p)
	}

	token := seedScopedTokenSubject(t, h.store, h.tenant, "p3l2-switch-operator", "keys:read", "keys:write", "certs:issue")
	startFor := func(member, key string) (int, []byte) {
		return secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/migrations/runs", token, key, map[string]any{
			"plan_id": "switch-p3l2", "new_authority_id": newRoot.ID, "revoke_predecessors": true,
			"waves": []any{map[string]any{"id": "canary", "ordinal": 1, "members": []any{map[string]any{
				"identity_id": member, "agent_id": agentRowID(h.tenant, h.agent), "trust_anchor_path": trustPath,
			}}}},
		})
	}
	if status, body := startFor(issueOnlyIdentity, "p3l2-start-issue-only"); status != http.StatusBadRequest || !strings.Contains(string(body), "cannot revoke") {
		t.Fatalf("a switch whose predecessor's vendor cannot revoke started: HTTP %d %s", status, body)
	}
	status, body = startFor(identityID, "p3l2-start")
	var started migration.Run
	if status != http.StatusCreated || json.Unmarshal(body, &started) != nil {
		t.Fatalf("start the switch: HTTP %d %s", status, body)
	}
	if b := started.Waves[0].Members[0].Binding; b.PredecessorExternalCAID != vendorID || b.PredecessorCAID != "" || b.PredecessorCertificateID != old.ID {
		t.Fatalf("member binding = %+v; want the vendor bound to revoke the predecessor", b)
	}

	state, err := agentrelay.NewHostRollbackStore(filepath.Join(root, "rollback"), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	profile := connector.LocalOpsConfig{
		AllowedRoots: []string{root},
		Actions:      []connector.LocalAction{{LogicalName: "nginx", Command: "/usr/bin/true", Timeout: 5 * time.Second}},
	}
	channel := &servedHostRelayChannel{client: h.client, identity: h.identity}
	runAgentPassAUD40(t, channel, profile, state, transport.JobOutcomeExecuted) // the new root is trusted first
	runAgentPassAUD40(t, channel, profile, state, transport.JobOutcomeVerified) // the successor is deployed and served
	assertMigrationStatusAUD40(t, h, started.ID, migration.RunRunning, migration.PhaseRevokingPredecessor)
	assertMigrationOutboxCountAUD40(t, h, started.ID, "revoke_predecessor", 1)
	if len(dc.Revocations()) != 0 {
		t.Fatalf("the vendor revoked before the revocation step: %v", dc.Revocations())
	}

	// The vendor holds the request for an approver: nothing is recorded and
	// the member has no verdict.
	dc.RequireRevocationApproval(true)
	revoke := incidentRevocationMessageAUD41(t, h, started.ID)
	if err := h.srv.obHandler.Deliver(ctx, revoke); err == nil || !strings.Contains(err.Error(), "revocation not confirmed") {
		t.Fatalf("a revocation the vendor holds for approval: %v; want it not yet confirmed", err)
	}
	if current, err := h.store.GetCertificate(ctx, h.tenant, old.ID); err != nil || current.Status == "revoked" {
		t.Fatalf("the predecessor is %q before the vendor accepted its revocation (%v)", current.Status, err)
	}
	assertMigrationStatusAUD40(t, h, started.ID, migration.RunRunning, migration.PhaseRevokingPredecessor)

	// The vendor accepts it.
	dc.RequireRevocationApproval(false)
	if err := h.srv.obHandler.Deliver(ctx, revoke); err != nil {
		t.Fatalf("revoke the predecessor at the vendor: %v", err)
	}
	revocations := dc.Revocations()
	if len(revocations) != 1 {
		t.Fatalf("the vendor revoked %v; want exactly the predecessor", revocations)
	}
	for _, reason := range revocations {
		if reason != "superseded" {
			t.Fatalf("the vendor recorded %q; want superseded", reason)
		}
	}
	event, found, err := h.log.EventByID(ctx, orchestrator.MigrationEventID(h.tenant, started.ID, "predecessor-revoked:"+revoke.IdempotencyKey))
	if err != nil || !found || event.Type != projections.EventCertificateRevoked {
		t.Fatalf("revocation event = %+v found %t err %v", event, found, err)
	}
	var revoked projections.CertificateRevoked
	if err := json.Unmarshal(event.Data, &revoked); err != nil {
		t.Fatal(err)
	}
	if revoked.Reason != string(crypto.RevocationReasonSuperseded) || revoked.Fingerprint != old.Fingerprint {
		t.Fatalf("revocation = %+v, want superseded for the vendor predecessor", revoked)
	}
	if current, err := h.store.GetCertificate(ctx, h.tenant, old.ID); err != nil || current.Status != "revoked" || current.RevocationReason != "superseded" {
		t.Fatalf("the predecessor in inventory = %s/%s %v; want revoked/superseded", current.Status, current.RevocationReason, err)
	}
	assertMigrationStatusAUD40(t, h, started.ID, migration.RunComplete, migration.PhaseComplete)
	row, err := h.store.GetMigrationRun(ctx, h.tenant, started.ID)
	if err != nil || row.Run.Waves[0].Members[0].RevocationVerdict != migration.VerdictVerified {
		t.Fatalf("the member's revocation verdict = %+v %v", row.Run.Waves[0].Members[0], err)
	}
}
