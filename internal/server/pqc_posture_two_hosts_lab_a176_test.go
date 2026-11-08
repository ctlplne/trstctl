// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/pqcmigration"
	"trstctl.com/trstctl/internal/store"

	agentrelay "trstctl.com/trstctl/internal/agent/relay"
)

// A176: a TLS posture change rolled out across two hosts, each with its own
// agent. Each host is a container network namespace holding a real Envoy, its
// REST xDS controller (deploy/demo/lab's Envoy fixture, run twice) and the
// product agent binary, enrolled with its own bootstrap token. One migration
// run binds a listener on each host; each posture job is pinned to that host's
// agent, which applies the change through its own Envoy's controller and signs
// a readback of its own TLS handshake; stock OpenSSL then sees TLS 1.3 with
// X25519MLKEM768 on both listeners and TLS 1.2 refused. The rollback returns
// to each agent, which restores the predecessor it recorded: TLS 1.2 works
// again on both and a hybrid-only TLS 1.3 handshake does not. Run by
// runners/a176-two-host-proof.sh, which builds the agent for Linux and the
// image it runs in; skipped otherwise.
func TestServedPostureRolloutAcrossTwoContainerHostsA176(t *testing.T) {
	lab, image := os.Getenv("TRSTCTL_A176_LAB_DIR"), os.Getenv("TRSTCTL_A176_AGENT_IMAGE")
	if lab == "" || image == "" {
		t.Skip("run runners/a176-two-host-proof.sh (the agent built for Linux and its image)")
	}
	h := newRoleHarnessWithEventOptions(t, []string{mtls.AgentRoleHost},
		[]string{agentrelay.KindPQCPosture, agentrelay.KindPQCPostureRollback},
		[]events.OpenOption{withSyntheticEventTypes},
		func(d *Deps) {
			runtime := pqcmigration.NewRuntime(d.Store)
			d.LicensedAPIOptionsFactory = runtime.APIOptionsFactory
			d.LicensedProjectionOptions = append(d.LicensedProjectionOptions, runtime.ProjectionOptions...)
			hooks := pqcmigration.HostAgentHooks{Store: d.Store, Log: d.Log, Progress: runtime.Progress, Key: d.KEK, TenantCrypto: d.TenantCrypto}
			d.PQCPostureJobOpen, d.PQCPostureJobResult = hooks.OpenJob, hooks.RecordResult
		})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	work := t.TempDir()
	write := func(name string, body []byte, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(work, name)
		if err := os.WriteFile(path, body, mode); err != nil { // #nosec G306 G703 -- public lab inputs the containers read (CWE-22)
			t.Fatal(err)
		}
		return path
	}
	// dockerTry runs one docker command of the lab's own; docker fails the
	// test on an error.
	dockerTry := func(args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, "docker", args...) // #nosec G204 G702 -- docker with the lab's own arguments and the runner's image (CWE-78)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		return out.String(), err
	}
	docker := func(args ...string) string {
		t.Helper()
		out, err := dockerTry(args...)
		if err != nil {
			t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return out
	}
	agentBinary, err := os.ReadFile(filepath.Join(lab, "trstctl-agent")) // #nosec G304 G703 -- the lab runner's build output (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	write("trstctl-agent", agentBinary, 0o755)
	write("agent-ca.pem", h.srv.AgentCACertPEM(), 0o644)
	httpPort := h.ts.URL[strings.LastIndex(h.ts.URL, ":")+1:]
	channelPort := h.channelAddr[strings.LastIndex(h.channelAddr, ":")+1:]
	// The fixture's own images and files, run with docker run on the default
	// bridge: the shared Docker daemon may have no address pool left for a new
	// network.
	fixture := filepath.Join("..", "..", "deploy", "demo", "lab")
	if fixture, err = filepath.Abs(fixture); err != nil {
		t.Fatal(err)
	}
	composeFile, err := os.ReadFile(filepath.Join(fixture, "docker-compose.pqc-envoy.yml")) // #nosec G304 -- the repository's own fixture (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	var nodeImage, envoyImage string
	for _, line := range strings.Split(string(composeFile), "\n") {
		if ref, ok := strings.CutPrefix(strings.TrimSpace(line), "image: "); ok {
			switch {
			case strings.HasPrefix(ref, "node@"):
				nodeImage = ref
			case strings.HasPrefix(ref, "envoyproxy/envoy@"):
				envoyImage = ref
			}
		}
	}
	if nodeImage == "" || envoyImage == "" {
		t.Fatalf("the Envoy fixture names no node or envoy image: %q %q", nodeImage, envoyImage)
	}
	// The fixture's Envoy finds its xDS controller by the compose service
	// name; here the two share a network namespace, so its address is loopback.
	bootstrap, err := os.ReadFile(filepath.Join(fixture, "pqc-envoy-bootstrap.json")) // #nosec G304 -- the repository's own fixture (CWE-22)
	if err != nil || !bytes.Contains(bootstrap, []byte(`"address": "pqc-envoy-controller"`)) {
		t.Fatalf("the Envoy fixture's bootstrap no longer names its controller: %v", err)
	}
	write("envoy-bootstrap.json", bytes.ReplaceAll(bootstrap, []byte(`"address": "pqc-envoy-controller"`), []byte(`"address": "127.0.0.1"`)), 0o644)

	type labHost struct {
		name, project, serverName, controllerPort, tlsPort, agentName, agentContainer, agentID, targetID string
		asset                                                                                            store.CryptoAsset
	}
	hosts := []*labHost{{name: "a"}, {name: "b"}}
	for i, host := range hosts {
		host.project = "trstctl-a176-" + host.name
		host.serverName = "edge-" + host.name + ".lab.test"
		host.controllerPort = fmt.Sprint(19281 + i)
		host.tlsPort = fmt.Sprint(11651 + i)
		host.agentName = "a176-edge-" + host.name
		host.agentContainer = "trstctl-a176-agent-" + host.name
		host.targetID = fmt.Sprintf("a1760000-0000-4000-8000-00000000000%d", i+1)
		certs := filepath.Join(work, "certs-"+host.name)
		if err := os.MkdirAll(certs, 0o755); err != nil { // #nosec G301 -- a disposable lab certificate the Envoy container reads
			t.Fatal(err)
		}
		docker("run", "--rm", "-v", certs+":/out", image, "sh", "-c",
			"openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN="+host.serverName+" -addext subjectAltName=DNS:"+host.serverName+
				" -keyout /out/key.pem -out /out/cert.pem 2>/dev/null && chmod 644 /out/key.pem /out/cert.pem")
		controller, envoy := host.project+"-controller", host.project+"-envoy"
		for _, name := range []string{envoy, controller} {
			name := name
			t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", "-v", name).Run() }) // #nosec G204 -- the lab's own container names (CWE-78)
		}
		docker("run", "-d", "--name", controller,
			"-p", "127.0.0.1:"+host.controllerPort+":19080", "-p", "127.0.0.1:"+host.tlsPort+":8443", "-p", "127.0.0.1:"+fmt.Sprint(19381+i)+":9901",
			"-v", "/state", "-v", filepath.Join(fixture, "pqc-envoy-controller.mjs")+":/app/controller.mjs:ro",
			"-v", filepath.Join(fixture, "pqc-envoy-lds.json")+":/app/initial-lds.json:ro", nodeImage, "node", "/app/controller.mjs")
		docker("run", "-d", "--name", envoy, "--network", "container:"+controller,
			"-v", filepath.Join(work, "envoy-bootstrap.json")+":/etc/envoy/bootstrap.json:ro", "-v", certs+":/etc/envoy-secrets:ro",
			envoyImage, "-c", "/etc/envoy/bootstrap.json")
		token, err := h.srv.agentEnroll.IssueBootstrapTokenWithRoles(ctx, h.tenant, host.agentName, []string{mtls.AgentRoleHost})
		if err != nil {
			t.Fatal(err)
		}
		write("token-"+host.name, []byte(token), 0o644)
		agentContainer := host.agentContainer
		t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", "-v", agentContainer).Run() }) // #nosec G204 -- the lab's own container name (CWE-78)
		script := strings.Join([]string{
			"socat TCP-LISTEN:18080,fork,reuseaddr,bind=127.0.0.1 TCP:host.docker.internal:" + httpPort + " &",
			"socat TCP-LISTEN:18443,fork,reuseaddr,bind=127.0.0.1 TCP:host.docker.internal:" + channelPort + " &",
			"sleep 1",
			"exec /work/trstctl-agent --name " + host.agentName + " --enroll-url http://127.0.0.1:18080 --allow-insecure-loopback-enrollment" +
				" --bootstrap-token-file /work/token-" + host.name + " --ca-bundle /work/agent-ca.pem --server 127.0.0.1:18443 --server-name " + h.serverName +
				" --key /state/agent.key --cert /state/agent.crt --relay-claim --host-rollback-dir /state/rollback",
		}, "\n")
		docker("run", "-d", "--name", host.agentContainer, "--network", "container:"+controller,
			"-v", work+":/work:ro", image, "sh", "-c", "mkdir -p /state/rollback && chmod 700 /state/rollback\n"+script)
	}

	// Each agent enrolls and heartbeats on its own.
	deadline := time.Now().Add(2 * time.Minute)
	for _, host := range hosts {
		host.agentID = agentRowID(h.tenant, host.agentName)
		for {
			agent, err := h.store.GetAgent(ctx, h.tenant, host.agentID)
			if err == nil && agent.LastSeenAt != nil {
				break
			}
			if time.Now().After(deadline) {
				logs, _ := dockerTry("logs", host.agentContainer)
				t.Fatalf("host %s's agent never heartbeated (%v):\n%s", host.name, err, logs)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	if hosts[0].agentID == hosts[1].agentID {
		t.Fatal("the two hosts' agents are one agent")
	}

	desired := connector.TLSPosture{MinimumVersion: "TLSv1.3", KeyExchangeGroups: []string{"X25519MLKEM768", "X25519"}}
	var assetIDs []string
	var bindings []map[string]any
	for _, host := range hosts {
		raw, _ := json.Marshal(map[string]any{"endpoint": "http://127.0.0.1:19080", "secret_name": "pqc-edge",
			"verify_address": "127.0.0.1:8443", "verify_server_name": host.serverName, "required_agent_id": host.agentID})
		if err := h.store.UpsertDeploymentTarget(ctx, store.DeploymentTarget{
			ID: host.targetID, TenantID: h.tenant, Name: "pqc-edge", Type: "envoy", Config: raw, Enabled: true, EnabledSet: true,
		}); err != nil {
			t.Fatal(err)
		}
		if host.asset, err = h.store.UpsertCryptoAsset(ctx, store.CryptoAsset{
			TenantID: h.tenant, Kind: "tls-endpoint", Location: host.serverName + ":8443", Protocol: "TLSv1.2", Strength: "acceptable",
		}); err != nil {
			t.Fatal(err)
		}
		assetIDs = append(assetIDs, host.asset.ID)
		bindings = append(bindings, map[string]any{"asset_id": host.asset.ID, "target_id": host.targetID, "desired": desired})
	}

	probe := func(host *labHost, args ...string) (string, error) {
		return dockerTry(append([]string{"run", "--rm", image, "sh", "-c",
			"openssl s_client -connect host.docker.internal:" + host.tlsPort + " -servername " + host.serverName + " -brief " +
				strings.Join(args, " ") + " </dev/null"}, []string{}...)...)
	}
	// Each Envoy serves its listener once it has read it from its controller.
	for _, host := range hosts {
		ready := time.Now().Add(time.Minute)
		for {
			out, err := probe(host, "-tls1_2")
			if err == nil {
				break
			}
			if time.Now().After(ready) {
				logs, _ := dockerTry("logs", "--tail", "30", host.project+"-envoy")
				t.Fatalf("host %s before the rollout: TLS 1.2 refused: %v\n%s\n== envoy\n%s", host.name, err, out, logs)
			}
			time.Sleep(time.Second)
		}
	}

	tok := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:issue")
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/pqc/migrations", tok, "a176-start", map[string]any{
		"asset_ids": assetIDs, "target_algorithm": "ML-DSA-65", "protocol": "acme", "tls_bindings": bindings,
	})
	var started struct {
		RunID             string `json:"run_id"`
		TLSFindingsQueued int    `json:"tls_findings_queued"`
	}
	if status != http.StatusAccepted || json.Unmarshal(body, &started) != nil || started.TLSFindingsQueued != 2 {
		t.Fatalf("start the rollout across both hosts = %d %s", status, body)
	}
	pinned := map[string]string{}
	rows, err := h.store.SystemPool().Query(ctx, `SELECT effect_lane, COALESCE(required_agent_id::text,'') FROM outbox
		WHERE tenant_id=$1 AND destination=$2`, h.tenant, agentrelay.KindPQCPosture)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var lane, agentID string
		if err := rows.Scan(&lane, &agentID); err != nil {
			t.Fatal(err)
		}
		pinned[lane] = agentID
	}
	rows.Close()
	for _, host := range hosts {
		if pinned["pqc-posture:target:"+host.targetID] != host.agentID {
			t.Fatalf("posture rows %v; want host %s's job pinned to its own agent %s", pinned, host.name, host.agentID)
		}
	}

	progress := func() pqcmigration.RunProgressResponse {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/pqc/migrations/"+started.RunID, tok, nil)
		var out pqcmigration.RunProgressResponse
		if status != http.StatusOK || json.Unmarshal(body, &out) != nil {
			t.Fatalf("progress = %d %s", status, body)
		}
		return out
	}
	await := func(what string, done func(pqcmigration.RunProgressResponse) bool) pqcmigration.RunProgressResponse {
		t.Helper()
		deadline := time.Now().Add(3 * time.Minute)
		for {
			p := progress()
			if done(p) {
				return p
			}
			if time.Now().After(deadline) {
				var logs strings.Builder
				for _, host := range hosts {
					out, _ := dockerTry("logs", "--tail", "40", host.agentContainer)
					logs.WriteString("== " + host.agentContainer + "\n" + out)
				}
				t.Fatalf("%s: progress %+v\n%s", what, p, logs.String())
			}
			time.Sleep(time.Second)
		}
	}
	applied := await("both hosts apply the posture", func(p pqcmigration.RunProgressResponse) bool { return p.Applied == 2 })
	readbacks := map[string]string{}
	for _, f := range applied.Findings {
		if f.HostReadback == nil || f.HostReadback.Served.KeyExchangeGroup != "X25519MLKEM768" {
			t.Fatalf("finding %+v has no signed hybrid readback", f)
		}
		readbacks[f.HostReadback.AgentID] = f.HostReadback.Served.ServerName
	}
	for _, host := range hosts {
		if readbacks[host.agentID] != host.serverName {
			t.Fatalf("readbacks %v; want host %s's agent to have signed its own listener's", readbacks, host.name)
		}
		out, err := probe(host, "-tls1_3", "-groups", "X25519MLKEM768")
		if err != nil || !strings.Contains(out, "TLSv1.3") || !strings.Contains(out, "X25519MLKEM768") {
			t.Fatalf("host %s after the rollout: hybrid TLS 1.3 = %v\n%s", host.name, err, out)
		}
		if out, err := probe(host, "-tls1_2"); err == nil {
			t.Fatalf("host %s after the rollout still accepts TLS 1.2:\n%s", host.name, out)
		}
	}

	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/pqc/migrations/"+started.RunID+"/rollback", tok,
		"a176-rollback", map[string]any{"asset_ids": assetIDs, "reason": "a176 two-host rollback"})
	if status != http.StatusAccepted {
		t.Fatalf("rollback = %d %s", status, body)
	}
	await("both hosts restore their predecessors", func(p pqcmigration.RunProgressResponse) bool { return p.RolledBack == 2 })
	for _, host := range hosts {
		if out, err := probe(host, "-tls1_2"); err != nil {
			t.Fatalf("host %s after the rollback: TLS 1.2 refused: %v\n%s", host.name, err, out)
		}
		if out, err := probe(host, "-tls1_3", "-groups", "X25519MLKEM768"); err == nil {
			t.Fatalf("host %s after the rollback still negotiates hybrid TLS 1.3:\n%s", host.name, out)
		}
	}
	t.Logf("A176: run %s rolled out to %s (%s) and %s (%s), each through its own agent, and rolled back", started.RunID,
		hosts[0].serverName, hosts[0].agentID, hosts[1].serverName, hosts[1].agentID)
}
