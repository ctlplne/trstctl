// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/sshtrust"
	"trstctl.com/trstctl/internal/agent/sshtrustfleet"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/sshtrustrollout"
	"trstctl.com/trstctl/internal/store"
)

const fleetSSHDConfig = "/etc/ssh/sshd_config"
const fleetSSHDKeys = "/etc/ssh/trstctl/trusted_user_ca_keys"

type fleetDockerFS struct {
	t    *testing.T
	name string
}

func (f fleetDockerFS) allowed(path string) bool {
	return path == fleetSSHDConfig || path == fleetSSHDKeys
}
func (f fleetDockerFS) ReadFile(path string) ([]byte, error) {
	if !f.allowed(path) {
		return nil, errors.New("unowned SSH fixture path")
	}
	return pamDockerOutput(f.t, 10*time.Second, "exec", f.name, "cat", path)
}
func (f fleetDockerFS) Exists(path string) bool { _, err := f.ReadFile(path); return err == nil }
func (f fleetDockerFS) Remove(path string) error {
	if !f.allowed(path) {
		return errors.New("unowned SSH fixture path")
	}
	_, err := pamDockerOutput(f.t, 10*time.Second, "exec", f.name, "rm", "-f", "--", path)
	return err
}
func (f fleetDockerFS) WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	if !f.allowed(path) {
		return errors.New("unowned SSH fixture path")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Fixed script and positional arguments; public file bytes arrive on stdin.
	script := `set -eu; target=$1; mode=$2; temporary=$(mktemp "${target}.a226-XXXXXX"); trap 'rm -f -- "$temporary"' EXIT; cat > "$temporary"; chmod "$mode" "$temporary"; mv -f -- "$temporary" "$target"`
	command := exec.CommandContext(ctx, "docker", "exec", "-i", f.name, "sh", "-c", script, "a226", path, fmt.Sprintf("%o", mode.Perm())) // #nosec G204 -- fixed operations on one owned SSH test container, with allowlisted public paths (CWE-78).
	command.Stdin = bytes.NewReader(data)
	out, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("fixture atomic public write: %w: %s", err, out)
	}
	return nil
}

type fleetSSHClient struct {
	t                            *testing.T
	sshd                         pamSSHD
	key, certificate, knownHosts string
}

func (c fleetSSHClient) run(ctx context.Context) ([]byte, error) {
	args := []string{"-F", "/dev/null", "-i", c.key, "-o", "CertificateFile=" + c.certificate, "-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes", "-o", "PreferredAuthentications=publickey", "-o", "UserKnownHostsFile=" + c.knownHosts, "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "BatchMode=yes", "-o", "ConnectTimeout=2", "-p", strconv.Itoa(c.sshd.Port), "alice@127.0.0.1", "true"}
	return exec.CommandContext(ctx, "ssh", args...).CombinedOutput() // #nosec G204 -- stock SSH against the owned container, with an exact host-key pin and public certificate (CWE-78).
}
func (c fleetSSHClient) check(ctx context.Context) error {
	deadline := time.Now().Add(5 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		_, last = c.run(ctx)
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return last
}
func (c fleetSSHClient) refused() {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(c.t.Context(), 8*time.Second)
	defer cancel()
	out, err := c.run(ctx)
	if err == nil || !bytes.Contains(out, []byte("Permission denied")) {
		c.t.Fatalf("SSH did not refuse the untrusted CA: err=%v output=%s", err, out)
	}
}

type fleetDockerChecks struct {
	t              *testing.T
	name           string
	healthy, prior fleetSSHClient
	failFirst      bool
	calls          int
}

func (c *fleetDockerChecks) Validate(ctx context.Context) error {
	_, err := pamDockerOutput(c.t, 10*time.Second, "exec", c.name, "/usr/sbin/sshd", "-t", "-f", fleetSSHDConfig)
	return err
}
func (c *fleetDockerChecks) Reload(ctx context.Context) error {
	_, err := pamDockerOutput(c.t, 10*time.Second, "exec", c.name, "kill", "-HUP", "1")
	return err
}
func (c *fleetDockerChecks) HealthCheck(ctx context.Context) error {
	c.calls++
	if c.failFirst {
		if c.calls == 1 {
			return errors.New("forced owned-host health failure")
		}
		return c.prior.check(ctx)
	}
	return c.healthy.check(ctx)
}

func approveFleetFixture(t *testing.T, h *servedHarness, token, label, public string, agents []string) store.SSHTrustFleetRollout {
	t.Helper()
	code, body := secretsReq(t, h, http.MethodPost, "/api/v1/ssh/trust-fleet/preview", token, map[string]any{"name": label, "reason": "Add the host-operator-staged public CA", "public_ca_key": public, "agent_ids": agents})
	if code != 200 {
		t.Fatalf("preview=%d %s", code, body)
	}
	var preview api.SSHTrustFleetPreview
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatal(err)
	}
	code, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/trust-fleet/approvals", token, label+"-approval", preview)
	if code != 201 {
		t.Fatalf("request approval=%d %s", code, body)
	}
	var approval api.SSHTrustFleetApproval
	if err := json.Unmarshal(body, &approval); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < approval.RequiredApprovals; i++ {
		reviewer := seedScopedTokenSubject(t, h.store, h.tenant, fmt.Sprintf("%s-reviewer-%d", label, i), "certs:issue")
		code, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/approval-requests/"+approval.ApprovalRequestID+"/approvals", reviewer, fmt.Sprintf("%s-decision-%d", label, i), map[string]any{"intent_digest": approval.ApprovalIntentDigest})
		if code != 200 && code != 201 {
			t.Fatalf("approve=%d %s", code, body)
		}
	}
	code, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/trust-fleet/rollouts", token, label+"-start", approval)
	if code != 202 {
		t.Fatalf("start=%d %s", code, body)
	}
	var rollout store.SSHTrustFleetRollout
	if err := json.Unmarshal(body, &rollout); err != nil {
		t.Fatal(err)
	}
	return rollout
}

func TestServedSSHTrustFleetChangesOpenSSHThroughSignedJobs(t *testing.T) {
	for _, tool := range []string{"docker", "ssh-keygen", "ssh"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("real OpenSSH proof requires %s: %v", tool, err)
		}
	}
	if out, err := pamDockerOutput(t, 15*time.Second, "version", "--format", "{{.Server.Version}}"); err != nil {
		t.Fatalf("Docker proof unavailable: %v %s", err, out)
	}
	h := newOperatingServedHarness(t, config.Protocols{SSH: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}, SSHUserPrincipals: []string{"alice"}}, withAgentChannel, func(d *Deps) {
		d.AgentClaimableJobKinds = []string{sshtrustrollout.Destination}
		d.RequiredApprovals = 2
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); h.srv.serveAgentChannel(ctx, ln) }()
	t.Cleanup(func() { cancel(); <-done })
	token := seedScopedTokenSubject(t, h.store, h.tenant, "a226-openssh-requester", "agents:read", "agents:write", "certs:issue", "certs:read")
	caPublic, err := h.srv.protocols.ssh.AuthorityKey()
	if err != nil {
		t.Fatal(err)
	}
	_, fingerprint, err := sshtrustrollout.CanonicalPublicCAKey(caPublic)
	if err != nil {
		t.Fatal(err)
	}
	keyPath, publicKey := generatePAMSSHKey(t)
	// The prior CA is a stock-client fixture. Only its public key enters Docker.
	priorCA := filepath.Join(t.TempDir(), "prior_ca")
	priorPublic := genSSHKey(t, priorCA)
	command := exec.Command("ssh-keygen", "-s", priorCA, "-I", "a226-prior-user", "-n", "alice", "-V", "+30m", keyPath+".pub") // #nosec G204 -- stock reference signing with a disposable fixture key in a private test directory (CWE-78).
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("prior certificate: %v %s", err, out)
	}
	priorCertificate, err := os.ReadFile(keyPath + "-cert.pub") // #nosec G304,G703 -- stock ssh-keygen produced this public certificate in the owned private test directory (CWE-22).
	if err != nil {
		t.Fatal(err)
	}
	priorCertPath := keyPath + "-prior.pub"
	if err := os.WriteFile(priorCertPath, priorCertificate, 0o600); err != nil { // #nosec G703 -- retain the owned generated public certificate beside its fixture key; no external path input (CWE-22).
		t.Fatal(err)
	}
	// Remove the automatic sidecar: the negative test must not authenticate with
	// the old certificate while explicitly presenting the new one.
	if err := os.Remove(keyPath + "-cert.pub"); err != nil {
		t.Fatal(err)
	}
	code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/certificates", token, "a226-user-cert", map[string]any{"certificate_type": "user", "public_key": publicKey, "key_id": "a226-new-user", "principals": []string{"alice"}, "ttl_seconds": 1800})
	if code != 201 {
		t.Fatalf("issue user cert=%d %s", code, body)
	}
	var certificate api.SSHCertificate
	if err := json.Unmarshal(body, &certificate); err != nil {
		t.Fatal(err)
	}
	newCertPath := keyPath + "-new.pub"
	if err := os.WriteFile(newCertPath, []byte(certificate.Certificate), 0o600); err != nil {
		t.Fatal(err)
	}
	type host struct {
		agent                *krlAgent
		sshd                 pamSSHD
		fs                   fleetDockerFS
		checks               *fleetDockerChecks
		policy               string
		newClient, oldClient fleetSSHClient
		before               []byte
	}
	hosts := make([]host, 3)
	ids := []string{}
	for i := range hosts {
		sshd := startPAMSSHD(t, priorPublic)
		agent := enrollKRLAgent(t, h, ln.Addr().String(), fmt.Sprintf("a226-host-%d", i), []string{mtls.AgentRoleHost})
		fs := fleetDockerFS{t: t, name: sshd.Name}
		before, err := fs.ReadFile(fleetSSHDKeys)
		if err != nil {
			t.Fatal(err)
		}
		hostKey, err := pamDockerOutput(t, 10*time.Second, "exec", sshd.Name, "cat", "/etc/ssh/ssh_host_ed25519_key.pub")
		if err != nil {
			t.Fatal(err)
		}
		known := filepath.Join(t.TempDir(), "known_hosts")
		line := fmt.Sprintf("[127.0.0.1]:%d %s", sshd.Port, hostKey)
		if err := os.WriteFile(known, []byte(line), 0o600); err != nil {
			t.Fatal(err)
		}
		newClient := fleetSSHClient{t: t, sshd: sshd, key: keyPath, certificate: newCertPath, knownHosts: known}
		oldClient := newClient
		oldClient.certificate = priorCertPath
		if err := oldClient.check(t.Context()); err != nil {
			t.Fatalf("known-good predecessor SSH login: %v", err)
		}
		newClient.refused()
		policy := "sha256:" + crypto.SHA256Hex([]byte(sshd.Name+"\x00"+fleetSSHDConfig+"\x00"+fleetSSHDKeys+"\x00"+fingerprint))
		fleetHeartbeat(t, agent, i < 2, fingerprint, policy)
		checks := &fleetDockerChecks{t: t, name: sshd.Name, healthy: newClient, prior: oldClient}
		hosts[i] = host{agent: agent, sshd: sshd, fs: fs, checks: checks, policy: policy, newClient: newClient, oldClient: oldClient, before: before}
		ids = append(ids, agentRowID(h.tenant, agent.name))
	}
	rollout := approveFleetFixture(t, h, token, "a226-openssh", string(caPublic), ids)
	execute := func(index int, want string) {
		t.Helper()
		host := hosts[index]
		jobs, err := host.agent.client.ClaimJobs(t.Context(), &transport.ClaimJobsRequest{Kinds: []string{sshtrustrollout.Destination}, Limit: 1, LeaseSeconds: sshtrustfleet.LeaseSeconds})
		if err != nil || len(jobs.Jobs) != 1 {
			t.Fatalf("claim host%d=%+v %v", index, jobs, err)
		}
		job := jobs.Jobs[0]
		queued, err := sshtrustrollout.DecodeCommand(bytes.NewReader(job.Payload))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(job.Payload, []byte(fleetSSHDConfig)) || bytes.Contains(job.Payload, []byte("kill -HUP")) {
			t.Fatal("network job selected local paths or commands")
		}
		local := sshtrustrollout.LocalAuthority{Enabled: true, Confirmed: true, AllowedCAFingerprint: fingerprint, AgentID: ids[index], ReadinessDigest: host.policy}
		report, applyErr := sshtrustfleet.ExecuteAt(t.Context(), h.tenant, sshtrust.Config{FS: host.fs, Reloader: host.checks, SSHDConfigPath: fleetSSHDConfig, TrustedUserCAKeysPath: fleetSSHDKeys}, local, queued, time.Now().UTC())
		if report.State != want {
			t.Fatalf("host%d effect=%+v err=%v", index, report, applyErr)
		}
		if want == "failed" && report.Rollback != "verified" {
			t.Fatalf("prior sshd was not verified after rollback: %+v", report)
		}
		raw, digest, err := report.Encode()
		if err != nil {
			t.Fatal(err)
		}
		outcome := transport.JobOutcomeVerified
		if want != "verified" {
			outcome = transport.JobOutcomeVerifyFailed
		}
		signed := signedJobReport(t, host.agent.identity, job.JobID, job.Attempt, outcome, string(raw), digest)
		accepted, err := host.agent.client.ReportJobResult(t.Context(), signed)
		if err != nil || !accepted.Accepted {
			t.Fatalf("signed host%d receipt=%+v %v", index, accepted, err)
		}
		if want == "verified" {
			if err := host.newClient.check(t.Context()); err != nil {
				t.Fatal(err)
			}
			// A local retry still validates/reloads/reads back; it writes no duplicate CA.
			repeat, err := sshtrustfleet.ExecuteAt(t.Context(), h.tenant, sshtrust.Config{FS: host.fs, Reloader: host.checks, SSHDConfigPath: fleetSSHDConfig, TrustedUserCAKeysPath: fleetSSHDKeys}, local, queued, time.Now().UTC())
			if err != nil || repeat.Changed || repeat.State != "verified" {
				t.Fatalf("retry effect=%+v %v", repeat, err)
			}
			installed, err := host.fs.ReadFile(fleetSSHDKeys)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Count(installed, bytes.TrimSpace(queued.PublicCAKey)) != 1 {
				t.Fatal("trust retry duplicated the public CA")
			}
		}
	}
	execute(0, "verified")
	execute(1, "verified")
	code, body = secretsReq(t, h, http.MethodGet, "/api/v1/ssh/trust-fleet/rollouts/"+rollout.ID, token, nil)
	if code != 200 {
		t.Fatalf("read source-bound rollout=%d %s", code, body)
	}
	var verified store.SSHTrustFleetRollout
	if err := json.Unmarshal(body, &verified); err != nil {
		t.Fatal(err)
	}
	if verified.State != "verified" || len(verified.Hosts) != 3 {
		t.Fatalf("fleet effect not bound to actual hosts: %s", body)
	}
	for index, id := range ids {
		found := false
		for _, host := range verified.Hosts {
			if host.AgentID != id {
				continue
			}
			found = true
			want := "verified"
			if index == 2 {
				want = "skipped"
			}
			if host.State != want {
				t.Fatalf("host %s state=%s want=%s", id, host.State, want)
			}
			if index < 2 && (host.Receipt == nil || host.Receipt.AgentID != id || host.ReceiptEventID == "") {
				t.Fatalf("host %s lacks its own bound receipt", id)
			}
		}
		if !found {
			t.Fatalf("reviewed host %s disappeared", id)
		}
	}
	skipped, err := hosts[2].agent.client.ClaimJobs(t.Context(), &transport.ClaimJobsRequest{Kinds: []string{sshtrustrollout.Destination}, Limit: 1, LeaseSeconds: 120})
	if err != nil || len(skipped.Jobs) != 0 {
		t.Fatalf("opt-out got work: %+v %v", skipped, err)
	}
	unchanged, err := hosts[2].fs.ReadFile(fleetSSHDKeys)
	if err != nil || !bytes.Equal(unchanged, hosts[2].before) {
		t.Fatalf("opt-out trust changed: %v", err)
	}
	hosts[2].newClient.refused()
	// A later explicit local opt-in gets its own new approval. A failed health
	// check restores the prior CA and proves the old certificate still logs in.
	fleetHeartbeat(t, hosts[2].agent, true, fingerprint, hosts[2].policy)
	hosts[2].checks.failFirst = true
	failedRollout := approveFleetFixture(t, h, token, "a226-rollback", string(caPublic), []string{ids[2]})
	execute(2, "failed")
	unchanged, err = hosts[2].fs.ReadFile(fleetSSHDKeys)
	if err != nil || !bytes.Equal(unchanged, hosts[2].before) {
		t.Fatal("rollback did not preserve exact prior trust")
	}
	hosts[2].newClient.refused()
	if err := hosts[2].oldClient.check(t.Context()); err != nil {
		t.Fatal(err)
	}
	code, body = secretsReq(t, h, http.MethodGet, "/api/v1/ssh/trust-fleet/rollouts/"+failedRollout.ID, token, nil)
	if code != 200 || !bytes.Contains(body, []byte(`"state":"attention_required"`)) || !bytes.Contains(body, []byte(`"rollback":"verified"`)) {
		t.Fatalf("rollback claimed apply completion: %d %s", code, body)
	}
}
