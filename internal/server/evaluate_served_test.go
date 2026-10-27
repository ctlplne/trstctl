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
	"sync"
	"testing"
	"time"

	agentrelay "trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/cli/evaluate"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// TestServedEvaluationJourneyA188 runs the design-partner evaluation kit
// against a lab target: a TLS listener that serves whatever a real host agent
// (the shipping relay loop, in process) installs into its certificate files.
// The journey passes every step, its pack signs and verifies offline, and the
// same journey against a closed port fails at discovery, skips what depends on
// it, and still exports the audit record.
func TestServedEvaluationJourneyA188(t *testing.T) {
	ctx := t.Context()
	auditKey := testAuditSigningKey(t)
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, []string{"connector.deploy", agentJobKindEndpointRenew},
		func(d *Deps) { d.AuditSigningKey = auditKey })
	const name = "eval.lab.test"

	// The lab target starts out serving a certificate trstctl did not issue.
	root := t.TempDir()
	certPath, keyPath := filepath.Join(root, "listener.crt"), filepath.Join(root, "listener.key")
	bootCert, bootKey := issueHostPair(t, h, name)
	defer secret.Wipe(bootKey)
	bootLeaf, err := certinfo.LeafDER(bootCert)
	if err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string][]byte{certPath: bootCert, keyPath: bootKey} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsServer, err := mtls.ServerCertFromFiles(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer.SetReloadCheckInterval(time.Millisecond)
	httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })} // #nosec G112 -- loopback fixture is closed below (CWE-400)
	serveDone := make(chan error, 1)
	go func() { serveDone <- tlsServer.ServeHTTPS(httpServer, listener) }()
	t.Cleanup(func() {
		_ = httpServer.Close()
		if serveErr := <-serveDone; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			t.Errorf("lab listener: %v", serveErr)
		}
	})
	profilePath := filepath.Join(root, "host-profile.json")
	profileJSON, err := json.Marshal(agentrelay.HostProfile{
		AllowedRoots: []string{root},
		Actions: []agentrelay.HostAction{{
			LogicalName: "nginx", Command: "/usr/bin/touch", Args: []string{filepath.Join(root, "reloaded")}, TimeoutSecs: 5,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profilePath, profileJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	profile, err := agentrelay.LoadHostProfile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	// The host agent announces itself, as a running agent does on start.
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "evaluation-lab", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	targetConfig, err := json.Marshal(map[string]any{
		"cert_path": certPath, "key_path": keyPath,
		"verify_address": listener.Addr().String(), "verify_server_name": name,
		"executor": "agent", "required_agent_id": agentRowID(h.tenant, h.agent),
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := h.srv.orch.UpsertDeploymentTarget(ctx, h.tenant, store.DeploymentTarget{
		Name: "evaluation-lab", Type: "nginx", Config: targetConfig, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// The control plane's workers and the host agent run as they would in a
	// deployment, until the test ends.
	pumpCtx, stopPump := context.WithCancel(context.Background())
	var pumping sync.WaitGroup
	pumping.Add(1)
	go func() {
		defer pumping.Done()
		channel := &servedHostRelayChannel{client: h.client, identity: h.identity}
		for pumpCtx.Err() == nil {
			_, _ = h.srv.outbox.DispatchScoped(pumpCtx, h.srv.obHandler, orchestrator.DestinationScope{})
			_, _ = agentrelay.RunOnceWithHost(pumpCtx, channel, http.DefaultClient, profile, 4, 60)
			select {
			case <-pumpCtx.Done():
			case <-time.After(50 * time.Millisecond):
			}
		}
	}()
	t.Cleanup(func() { stopPump(); pumping.Wait() })

	token := seedScopedTokenSubject(t, h.store, h.tenant, "design-partner", "*")
	options := evaluate.Options{Server: h.ts.URL, Token: token, HTTPClient: h.ts.Client(), DeploymentTarget: target.ID,
		Timeout: 45 * time.Second, PollInterval: 100 * time.Millisecond}
	pack, err := evaluate.Evaluate(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	steps := map[string]evaluate.Step{}
	for _, s := range pack.Steps {
		steps[s.Name] = s
		if s.Status != evaluate.StatusPass {
			t.Errorf("%s = %s: %s", s.Name, s.Status, s.Detail)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	issued := steps[evaluate.StepIssuance].Evidence["fingerprint"]
	if pack.Verdict != evaluate.StatusPass || pack.Summary.Passed != 8 || pack.Target.Endpoint != listener.Addr().String() || pack.Target.Name != name ||
		steps[evaluate.StepDiscovery].Evidence["served_fingerprint"] != crypto.SHA256Hex(bootLeaf) ||
		steps[evaluate.StepVerification].Evidence["served_fingerprint"] != issued ||
		steps[evaluate.StepRenewal].Evidence["fingerprint"] == issued ||
		steps[evaluate.StepRevocation].Evidence["ocsp_status"] != "revoked" ||
		steps[evaluate.StepAuditExport].Evidence["record_count"] == "" || pack.AuditExport == nil {
		t.Fatalf("pack = %+v", pack)
	}

	// Signed by the audit-evidence key, the pack checks offline against the
	// audit keys the deployment publishes; an edited pack does not.
	status, jwks := doBearer(t, h.ts, http.MethodGet, "/api/v1/audit/verification-keys", token, "", nil)
	auditKeys, err := jose.ParseJWKSet(jwks)
	if status != http.StatusOK || err != nil {
		t.Fatalf("audit verification keys = %d %v", status, err)
	}
	if err := evaluate.Sign(&pack, auditKey, auditKey.KeyID()); err != nil {
		t.Fatal(err)
	}
	signed, err := json.MarshalIndent(pack, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if verified, kid, err := evaluate.Verify(signed, auditKeys); err != nil || kid != auditKey.KeyID() || verified.Verdict != evaluate.StatusPass {
		t.Fatalf("verify = %s, %v", kid, err)
	}
	edited := pack
	edited.Summary.Failed = 0
	edited.Steps = append([]evaluate.Step(nil), pack.Steps...)
	edited.Steps[0].Detail = "edited"
	editedJSON, err := json.Marshal(edited)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := evaluate.Verify(editedJSON, auditKeys); err == nil {
		t.Fatal("an edited pack verified")
	}
	if err := evaluate.VerifyAuditExport(pack, auditKeys); err != nil {
		t.Fatalf("the pack's audit export did not verify with the published audit keys: %v", err)
	}

	// A forced failure: the endpoint is a closed port.
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unreachable := closed.Addr().String()
	_ = closed.Close()
	options.Endpoint = unreachable
	failed, err := evaluate.Evaluate(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	outcome := map[string]evaluate.Status{}
	for _, s := range failed.Steps {
		outcome[s.Name] = s.Status
	}
	// A journey that stopped before it created an identity has no record of
	// its own to export: skipped and saying why, never passed on other records
	// the tenant made meanwhile (an earlier run's background work included).
	if failed.Verdict != evaluate.StatusFail || outcome[evaluate.StepDiscovery] != evaluate.StatusFail ||
		outcome[evaluate.StepIssuance] != evaluate.StatusSkipped || outcome[evaluate.StepRevocation] != evaluate.StatusSkipped ||
		outcome[evaluate.StepAuditExport] != evaluate.StatusSkipped || failed.AuditExport != nil ||
		failed.Summary.Failed != 1 || failed.Summary.Skipped != 7 {
		t.Fatalf("unreachable endpoint = %+v", failed)
	}
}
