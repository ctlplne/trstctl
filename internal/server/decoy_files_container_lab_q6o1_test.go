// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Q6-O1 lab: the product agent built for Linux runs in a container as a host
// agent started with --decoy-ssh-keys, beside a real SSH key it inventories
// from the same directory. The agent's own scan sets nothing off; `cat` of the
// decoy in that container raises the decoy alert naming the host. Each host
// runs twice, as runners/q6o1-lab-proof.sh starts it: with CAP_SYS_ADMIN
// (fanotify: the alert names cat even after it exits) and without (inotify:
// the open alerts, its opener named while it still holds the file).
func TestServedDecoyFileOpenedOnAContainerHostQ6O1(t *testing.T) {
	lab, image := os.Getenv("TRSTCTL_Q6O1_LAB_DIR"), os.Getenv("TRSTCTL_Q6O1_AGENT_IMAGE")
	if lab == "" || image == "" {
		t.Skip("run runners/q6o1-lab-proof.sh (the agent built for Linux and its image)")
	}
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, nil, withIsolatedTenant)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	work := t.TempDir()
	write := func(name string, body []byte, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(work, name), body, mode); err != nil { // #nosec G306 G703 -- disposable lab inputs the container reads (CWE-22)
			t.Fatal(err)
		}
	}
	dockerTry := func(args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, "docker", args...) // #nosec G204 G702 -- docker with the lab's own arguments and the runner's image (CWE-78)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		return out.String(), err
	}
	agentBinary, err := os.ReadFile(filepath.Join(lab, "trstctl-agent")) // #nosec G304 G703 -- the lab runner's build output (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	write("trstctl-agent", agentBinary, 0o755)
	write("agent-ca.pem", h.srv.AgentCACertPEM(), 0o644)
	// A real key beside the decoy: the agent's private-key scan reports it,
	// which says the scan ran over the decoy's directory.
	realKey, _, err := crypto.GenerateSSHClientKey("deploy@q6o1-lab")
	if err != nil {
		t.Fatal(err)
	}
	write("id_ed25519", realKey, 0o644)
	secret.Wipe(realKey)
	httpPort := h.ts.URL[strings.LastIndex(h.ts.URL, ":")+1:]
	channelPort := h.channelAddr[strings.LastIndex(h.channelAddr, ":")+1:]
	const decoyPath = "/root/.ssh/id_ed25519_backup"

	alerts := func() []string {
		t.Helper()
		rows, err := h.store.SystemPool().Query(ctx,
			`SELECT payload FROM outbox WHERE tenant_id = $1 AND destination = 'notification.honeytoken' ORDER BY id`, h.tenant)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var alert struct {
				Detail string `json:"detail"`
			}
			if err := json.Unmarshal(raw, &alert); err != nil {
				t.Fatal(err)
			}
			out = append(out, alert.Detail)
		}
		return out
	}
	waitFor := func(container, what string, done func() bool) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Minute)
		for !done() {
			if time.Now().After(deadline) {
				logs, _ := dockerTry("logs", container)
				t.Fatalf("%s never happened:\n%s", what, logs)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}

	for _, run := range []struct {
		name string
		caps []string
	}{{"fanotify", []string{"--cap-add", "SYS_ADMIN"}}, {"inotify", nil}} {
		agentName := "q6o1-host-" + run.name
		container := "trstctl-q6o1-agent-" + run.name
		token, err := h.srv.agentEnroll.IssueBootstrapTokenWithRoles(ctx, h.tenant, agentName, []string{mtls.AgentRoleHost})
		if err != nil {
			t.Fatal(err)
		}
		write("token-"+run.name, []byte(token), 0o644)
		_, _ = dockerTry("rm", "-f", "-v", container)
		t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", "-v", container).Run() }) // #nosec G204 -- the lab's own container name (CWE-78)
		script := strings.Join([]string{
			"mkdir -p /root/.ssh /state && chmod 700 /root/.ssh /state && cp /work/id_ed25519 /root/.ssh/id_ed25519 && chmod 600 /root/.ssh/id_ed25519",
			"socat TCP-LISTEN:18080,fork,reuseaddr,bind=127.0.0.1 TCP:host.docker.internal:" + httpPort + " &",
			"socat TCP-LISTEN:18443,fork,reuseaddr,bind=127.0.0.1 TCP:host.docker.internal:" + channelPort + " &",
			"sleep 1",
			"exec /work/trstctl-agent --name " + agentName + " --enroll-url http://127.0.0.1:18080 --allow-insecure-loopback-enrollment" +
				" --bootstrap-token-file /work/token-" + run.name + " --ca-bundle /work/agent-ca.pem --server 127.0.0.1:18443 --server-name " + h.serverName +
				" --key /state/agent.key --cert /state/agent.crt --decoy-ssh-keys " + decoyPath + " --inventory-private-key-roots /root/.ssh",
		}, "\n")
		args := append([]string{"run", "-d", "--name", container}, run.caps...)
		args = append(args, "-v", work+":/work:ro", image, "sh", "-c", script)
		if out, err := dockerTry(args...); err != nil {
			t.Fatalf("start the %s host: %v\n%s", run.name, err, out)
		}

		// The decoy is registered under the host's name, and the agent's
		// private-key scan of the decoy's directory reported the real key.
		var decoyID string
		waitFor(container, run.name+" host's decoy registration", func() bool {
			files, err := h.store.ListDecoyFilesPage(ctx, h.tenant, "", 100)
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range files {
				if f.FileHost == agentName && f.FilePath == decoyPath {
					decoyID = f.ID
					return true
				}
			}
			return false
		})
		waitFor(container, run.name+" host's private-key inventory", func() bool {
			var n int
			if err := h.store.SystemPool().QueryRow(ctx,
				`SELECT count(*) FROM discovery_findings f JOIN discovery_sources s ON s.tenant_id = f.tenant_id AND s.id = f.source_id
				  WHERE f.tenant_id = $1 AND s.name = $2 AND f.ref LIKE '%/root/.ssh/id_ed25519'`,
				h.tenant, "agent:"+agentName+":private-key").Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n > 0
		})
		before := len(alerts())
		time.Sleep(2 * time.Second) // an open by the agent's own scan would have reached the control plane
		if got := alerts(); len(got) != before {
			t.Fatalf("the %s host's own scan set its decoy off: %v", run.name, got[before:])
		}
		var findings int
		if err := h.store.SystemPool().QueryRow(ctx,
			`SELECT count(*) FROM discovery_findings WHERE tenant_id = $1 AND ref LIKE '%id_ed25519_backup%'`, h.tenant).Scan(&findings); err != nil {
			t.Fatal(err)
		}
		if findings != 0 {
			t.Fatalf("the %s host's inventory reported its decoy (%d findings)", run.name, findings)
		}

		// Somebody on the host reads the decoy.
		if out, err := dockerTry("exec", container, "cat", decoyPath); err != nil || !strings.Contains(out, "OPENSSH PRIVATE KEY") {
			t.Fatalf("cat the decoy on the %s host: %v\n%s", run.name, err, out)
		}
		var detail string
		waitFor(container, run.name+" host's decoy alert", func() bool {
			got := alerts()
			if len(got) > before {
				detail = got[before]
				return true
			}
			return false
		})
		if !strings.Contains(detail, decoyPath) || !strings.Contains(detail, "on "+agentName) || !strings.Contains(detail, decoyID) {
			t.Fatalf("the %s host's alert %q does not name the decoy, its host and its id", run.name, detail)
		}
		// fanotify names the opener even after it exited: its command, and
		// its executable where the agent may read it.
		if run.name == "fanotify" && !strings.Contains(detail, "opened by cat") {
			t.Fatalf("the fanotify alert %q does not name cat", detail)
		}
		decoy, err := h.store.GetHoneyToken(ctx, h.tenant, decoyID)
		if err != nil || decoy.State != "triggered" || !strings.Contains(decoy.TriggerMethod, "seen by "+run.name) {
			t.Fatalf("the %s host's decoy after the read = %+v, %v", run.name, decoy, err)
		}
		t.Logf("%s host: alert %q; decoy %s first opened by %q (%s)", run.name, detail, decoy.ID, decoy.TriggerSubject, decoy.TriggerMethod)

		// inotify names an opener that still holds the file.
		if run.name == "inotify" {
			if out, err := dockerTry("exec", container, "sh", "-c", "exec 3<"+decoyPath+"; sleep 3"); err != nil {
				t.Fatalf("hold the decoy open: %v\n%s", err, out)
			}
			waitFor(container, "the inotify host's alert naming the holder", func() bool {
				for _, d := range alerts()[before:] {
					if strings.Contains(d, "opened by sh") || strings.Contains(d, "opened by sleep") {
						t.Logf("inotify host: alert %q", d)
						return true
					}
				}
				return false
			})
		}
		logs, _ := dockerTry("logs", container)
		t.Logf("%s host agent log:\n%s", run.name, logs)
	}
}
