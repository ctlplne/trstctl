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
	"sync"
	"testing"
	"time"

	agentrelay "trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/cli/evaluate"
	connectorwasm "trstctl.com/trstctl/internal/connector/wasm/host"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// newIncidentLab is the evaluation lab of TestServedEvaluationJourneyA188 — a
// real TLS listener the host agent deploys to and reloads — whose host profile
// also grants the target a containment: one pinned stop action, which here
// stops the listener as stopping nginx would.
func newIncidentLab(t *testing.T, name string) evaluate.Options {
	t.Helper()
	ctx := t.Context()
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost},
		[]string{"connector.deploy", agentJobKindEndpointRenew, agentrelay.KindEndpointContain},
		func(d *Deps) { d.AuditSigningKey = testAuditSigningKey(t) })

	root := t.TempDir()
	certPath, keyPath, stopFile := filepath.Join(root, "listener.crt"), filepath.Join(root, "listener.key"), filepath.Join(root, "stopped")
	bootCert, bootKey := issueHostPair(t, h, name)
	defer secret.Wipe(bootKey)
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
		Name: name, Type: "nginx", Config: targetConfig, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The host operator's grant: this target's listener, and the one action
	// that stops it — pinned and argument-free, as an operator writes it
	// ("logical_args": []).
	profilePath := filepath.Join(root, "host-profile.json")
	profileJSON, err := json.Marshal(map[string]any{
		"allowed_roots": []string{root},
		"actions": []map[string]any{
			{"logical_name": "nginx", "command": "/usr/bin/touch", "args": []string{filepath.Join(root, "reloaded")}, "timeout_seconds": 5},
			{"logical_name": "lab-stop", "logical_args": []string{}, "command": "/usr/bin/touch", "args": []string{stopFile}, "timeout_seconds": 5},
		},
		"containments": []agentrelay.HostContainment{{TargetID: target.ID, Address: listener.Addr().String(), ServerName: name, Action: "lab-stop"}},
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
	if _, err := connectorwasm.Builtin(); err != nil {
		t.Fatalf("connector sandbox: %v", err)
	}

	pumpCtx, stopPump := context.WithCancel(context.Background())
	var pumping sync.WaitGroup
	pumping.Add(2)
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
	// The stop action's effect: the listener closes, as nginx's would.
	go func() {
		defer pumping.Done()
		for pumpCtx.Err() == nil {
			if _, err := os.Stat(stopFile); err == nil {
				_ = httpServer.Close()
				return
			}
			select {
			case <-pumpCtx.Done():
			case <-time.After(20 * time.Millisecond):
			}
		}
	}()
	t.Cleanup(func() { stopPump(); pumping.Wait() })

	token := seedScopedTokenSubject(t, h.store, h.tenant, "design-partner", "*")
	return evaluate.Options{Server: h.ts.URL, Token: token, HTTPClient: h.ts.Client(), DeploymentTarget: target.ID,
		Journeys: []string{evaluate.JourneyCertificate, evaluate.JourneyIncident},
		Timeout:  45 * time.Second, PollInterval: 100 * time.Millisecond}
}

// A249: `trstctl evaluate --journeys certificate,incident` passes against a
// served control plane and a host agent: after the certificate journey, the
// incident journey previews the compromise of the deployed certificate's key
// effect-free, rehearses it as a game day, revokes it at the CA and stops the
// listener through the one reviewed command, and sees both — the OCSP answer
// revoked and the endpoint no longer serving it. A forced failure is reported
// as one.
func TestServedEvaluateIncidentJourneyA249(t *testing.T) {
	statuses := func(steps []evaluate.Step) string {
		out := make([]string, 0, len(steps))
		for _, s := range steps {
			out = append(out, s.Name+"="+string(s.Status)+" ("+s.Detail+")")
		}
		return strings.Join(out, "\n")
	}
	// Each lab is its own subtest: its agent and workers stop before the next
	// lab starts, since both enroll the same agent in the same tenant.
	t.Run("responds", func(t *testing.T) {
		pack, err := evaluate.Evaluate(t.Context(), newIncidentLab(t, "incident.lab.test"))
		if err != nil {
			t.Fatal(err)
		}
		if len(pack.Journeys) != 1 || pack.Verdict != evaluate.StatusPass || pack.Journeys[0].Verdict != evaluate.StatusPass {
			t.Fatalf("pack %s\ncertificate journey:\n%s\nincident journey:\n%s", pack.Verdict, statuses(pack.Steps), statuses(pack.Journeys[0].Steps))
		}
		steps := map[string]evaluate.Step{}
		for _, s := range pack.Journeys[0].Steps {
			steps[s.Name] = s
		}
		if steps[evaluate.StepIncidentContain].Evidence["containment_status"] != "containment_stopped" ||
			steps[evaluate.StepIncidentVerify].Evidence["ocsp_status"] != "revoked" ||
			steps[evaluate.StepIncidentVerify].Evidence["endpoint"] != "refused the handshake" ||
			!strings.Contains(steps[evaluate.StepIncidentRehearse].Detail, "mocked: matched") {
			t.Fatalf("incident evidence:\n%s", statuses(pack.Journeys[0].Steps))
		}
	})
	t.Run("forced failure", func(t *testing.T) {
		opts := newIncidentLab(t, "forced.incident.lab.test")
		opts.ForceFailure = evaluate.JourneyIncident
		forced, err := evaluate.Evaluate(t.Context(), opts)
		if err != nil {
			t.Fatal(err)
		}
		got := forced.Journeys[0].Steps
		if forced.Verdict != evaluate.StatusFail || len(got) != 4 || got[3].Status != evaluate.StatusFail ||
			got[0].Status != evaluate.StatusPass || got[2].Status != evaluate.StatusPass || !forced.Journeys[0].ForcedFailure ||
			!strings.Contains(got[3].Detail, "says revoked") {
			t.Fatalf("a forced incident failure: %s\ncertificate journey:\n%s\nincident journey:\n%s", forced.Verdict, statuses(forced.Steps), statuses(got))
		}
	})
}
