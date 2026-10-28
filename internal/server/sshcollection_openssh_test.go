// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/sshkeys"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/sshcollection"
	"trstctl.com/trstctl/internal/store"
)

type sshCollectionServedChannel struct {
	t       *testing.T
	h       *roleHarness
	reports []*transport.ReportJobResultRequest
}

func (c *sshCollectionServedChannel) ClaimJobs(ctx context.Context, kinds []string, limit, lease int) ([]relay.Job, error) {
	response, err := c.h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: kinds, Limit: limit, LeaseSeconds: lease})
	if err != nil {
		return nil, err
	}
	var jobs []relay.Job
	for _, job := range response.Jobs {
		jobs = append(jobs, relay.Job{JobID: job.JobID, Kind: job.Kind, Attempt: job.Attempt, Payload: job.Payload, LeaseExpiresUnix: job.LeaseExpiresUnix})
	}
	return jobs, nil
}
func (c *sshCollectionServedChannel) RedeemJobCredential(ctx context.Context, id int64, attempt int) (map[string][]byte, error) {
	response, err := c.h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: id, Attempt: attempt})
	if err != nil {
		return nil, err
	}
	material := map[string][]byte{}
	for _, item := range response.Items {
		material[item.Name] = item.Value
	}
	return material, nil
}
func (c *sshCollectionServedChannel) ExtendJobClaim(ctx context.Context, id int64, attempt int) (time.Time, error) {
	response, err := c.h.client.ReportJobResult(ctx, &transport.ReportJobResultRequest{JobID: id, Attempt: attempt, Outcome: transport.JobOutcomeExtend, LeaseSeconds: 120})
	if err != nil {
		return time.Time{}, err
	}
	if !response.Accepted {
		return time.Time{}, relay.ErrJobClaimLost
	}
	return time.Unix(response.LeaseExpiresUnix, 0), nil
}
func (c *sshCollectionServedChannel) ReportJobResult(ctx context.Context, id int64, attempt int, outcome, detail, digest string) (bool, error) {
	request := c.h.report(c.t, id, attempt, outcome, detail, digest)
	c.reports = append(c.reports, request)
	response, err := c.h.client.ReportJobResult(ctx, request)
	if err != nil {
		return false, err
	}
	return response.Accepted, nil
}

func startSSHCollectionContainer(t *testing.T, public, tenantCA []byte) (pamSSHD, string) {
	t.Helper()
	for _, tool := range []string{"docker", "ssh", "ssh-keygen"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	helper, err := os.ReadFile("../../deploy/ssh/trstctl-ssh-collect-v1")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"collector": helper, "reader.pub": public, "tenant_ca.pub": tenantCA, "policy.json": []byte(`{"config_path":"/etc/ssh/sshd_config","allowed_public_files":["/etc/ssh/tenant_ca.pub","/etc/ssh/ssh_host_ed25519_key-cert.pub"]}`)}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dockerfile := `FROM alpine:3.20
RUN apk add --no-cache openssh-server python3 sudo
RUN adduser -D -s /bin/sh trstctl_observe && echo 'trstctl_observe:fixture-disabled' | chpasswd && ssh-keygen -A && mkdir -p /etc/trstctl /usr/local/libexec /etc/ssh/collection_authorized_keys
COPY collector /usr/local/libexec/trstctl-ssh-collect-v1
COPY policy.json /etc/trstctl/ssh-collection-v1.json
COPY reader.pub /etc/ssh/collection_authorized_keys/trstctl_observe
COPY tenant_ca.pub /etc/ssh/tenant_ca.pub
RUN chmod 755 /usr/local/libexec/trstctl-ssh-collect-v1 && chmod 600 /etc/trstctl/ssh-collection-v1.json && chmod 644 /etc/ssh/collection_authorized_keys/trstctl_observe && printf 'trstctl_observe ALL=(root) NOPASSWD: /usr/local/libexec/trstctl-ssh-collect-v1 ""\n' > /etc/sudoers.d/trstctl-collect && chmod 440 /etc/sudoers.d/trstctl-collect
RUN touch /etc/ssh/not-permitted.krl
RUN ssh-keygen -q -s /etc/ssh/ssh_host_ecdsa_key -I a227-host -h -n localhost -V +1h /etc/ssh/ssh_host_ed25519_key.pub
RUN printf 'Port 22\nHostKey /etc/ssh/ssh_host_ed25519_key\nHostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub\nTrustedUserCAKeys /etc/ssh/tenant_ca.pub\nRevokedKeys /etc/ssh/not-permitted.krl\nPasswordAuthentication no\nPubkeyAuthentication yes\nAuthorizedKeysFile /etc/ssh/collection_authorized_keys/%%u\nPermitRootLogin no\nAllowUsers trstctl_observe\nDisableForwarding yes\nPermitUserRC no\nPermitUserEnvironment no\nPermitTTY no\nForceCommand /usr/bin/sudo -n /usr/local/libexec/trstctl-ssh-collect-v1\n' > /etc/ssh/sshd_config
CMD ["/usr/sbin/sshd","-D","-e","-f","/etc/ssh/sshd_config"]
`
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o600); err != nil {
		t.Fatal(err)
	}
	image := "trstctl-a227-sshd:" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if out, err := pamDockerOutput(t, 10*time.Minute, "build", "--load", "-t", image, dir); err != nil {
		t.Fatalf("owned sshd build: %v %s", err, out)
	}
	t.Cleanup(func() { pamDockerCleanup("image", "rm", "-f", image) })
	name := "trstctl-a227-sshd-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if out, err := pamDockerOutput(t, 30*time.Second, "run", "-d", "--pull=never", "--name", name, "-p", "127.0.0.1::22", image); err != nil {
		t.Fatalf("owned sshd run: %v %s", err, out)
	}
	t.Cleanup(func() { pamDockerCleanup("rm", "-f", name) })
	portOut, err := pamDockerOutput(t, 10*time.Second, "port", name, "22/tcp")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(strings.TrimSpace(string(portOut)), ":")
	port, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		t.Fatal(err)
	}
	hostPublic, err := pamDockerOutput(t, 10*time.Second, "exec", name, "cat", "/etc/ssh/ssh_host_ed25519_key.pub")
	if err != nil {
		t.Fatal(err)
	}
	info, err := sshkeys.ParsePublicKey(hostPublic)
	if err != nil {
		t.Fatal(err)
	}
	return pamSSHD{Name: name, Port: port}, info.FingerprintSHA256
}

func TestServedAgentlessSSHCollectsOpenSSHThroughVaultedRelayJob(t *testing.T) {
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{sshcollection.Destination}, func(d *Deps) {
		d.Protocols = config.Protocols{SSH: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}}
	})
	ctx := t.Context()
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "a227-openssh", Status: "active", Executors: &transport.ExecutorReport{Version: "a227-openssh", Kinds: []transport.ExecutorKind{{Kind: sshcollection.Destination}}}}); err != nil {
		t.Fatal(err)
	}
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	public, err := crypto.SSHPublicKeyFromSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	der, err := key.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(der)
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer secret.Wipe(private)
	const ref = "secret://ssh/a227-read-only"
	sealed, err := h.srv.sealTenantSecretForTest(ctx, h.tenant, "ssh/a227-read-only", private)
	if err != nil {
		t.Fatal(err)
	}
	seedApplicationSecretFixture(t, h.store, h.tenant, "ssh/a227-read-only", sealed)
	ca, err := h.srv.protocols.ssh.AuthorityKey()
	if err != nil {
		t.Fatal(err)
	}
	host, pin := startSSHCollectionContainer(t, public, ca)
	address := fmt.Sprintf("127.0.0.1:%d", host.Port)
	// The container build is not a running relay heartbeat loop. Refresh its
	// real authenticated presence after setup, before asking for a ready plan.
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "a227-openssh", Status: "active", Executors: &transport.ExecutorReport{Version: "a227-openssh", Kinds: []transport.ExecutorKind{{Kind: sshcollection.Destination}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.orch.UpsertDiscoverySegment(ctx, h.tenant, store.DiscoverySegment{Name: "a227-owned", Ranges: []string{"127.0.0.1"}, StalenessHours: 24}); err != nil {
		t.Fatal(err)
	}
	token := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write", "certs:read")
	sourceInput := map[string]any{"name": "a227-no-host-agent", "kind": sshcollection.SourceKind, "config": sshcollection.Config{Enabled: true, Segment: "a227-owned", RelayAgentID: agentRowID(h.tenant, h.agent), AllowLoopback: true, Hosts: []sshcollection.Host{{Address: address, Username: "trstctl_observe", HostKeyFingerprint: pin, CredentialRef: ref}}}}
	code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/sources", token, "a227-source", sourceInput)
	if code != 201 {
		t.Fatalf("source=%d %s", code, body)
	}
	var source store.DiscoverySource
	if err := json.Unmarshal(body, &source); err != nil {
		t.Fatal(err)
	}
	code, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/runs", token, "a227-run", map[string]any{"source_id": source.ID})
	if code != 202 && code != 201 {
		t.Fatalf("queue=%d %s", code, body)
	}
	var run store.DiscoveryRun
	if err := json.Unmarshal(body, &run); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	channel := &sshCollectionServedChannel{t: t, h: h}
	if n, err := relay.RunOnce(ctx, channel, nil, 1, 120); err != nil || n != 1 {
		t.Fatalf("real relay execution: %d %v", n, err)
	}
	if len(channel.reports) != 1 {
		t.Fatalf("reports=%d", len(channel.reports))
	}
	request := channel.reports[0]
	if request.Outcome != transport.JobOutcomeExecuted || bytes.Contains([]byte(request.Detail), private) || strings.Contains(request.Detail, "PRIVATE KEY") {
		t.Fatal("readback failed or exposed private material")
	}
	current, err := h.store.GetDiscoveryRun(ctx, h.tenant, run.ID)
	if err != nil || current.Status != "succeeded" || current.Discovered != 1 {
		t.Fatalf("run=%+v err=%v", current, err)
	}
	view, err := h.srv.SSHHostTrust(ctx, h.tenant)
	if err != nil || len(view.Hosts) != 1 {
		t.Fatalf("host trust=%+v %v", view, err)
	}
	observed := view.Hosts[0]
	if observed.TargetAddress != address || observed.AgentID != agentRowID(h.tenant, h.agent) || observed.CollectionMode != "agentless" || observed.UserCA != "tenant_ca" || observed.RevocationList != "unreadable" || len(observed.HostCertificates) != 1 || !observed.HostCertificates[0].SignatureVerified {
		t.Fatalf("remote evidence/provenance=%+v", observed)
	}
	var cliOut, cliErr bytes.Buffer
	cliEnv := cli.Env{Server: h.ts.URL, Token: token, Tenant: h.tenant, HTTPClient: h.ts.Client()}
	if exit := cli.Run(ctx, []string{"ssh", "fleet"}, cliEnv, strings.NewReader(""), &cliOut, &cliErr); exit != 0 || !bytes.Contains(cliOut.Bytes(), []byte(address)) || !bytes.Contains(cliOut.Bytes(), []byte(`"collection_mode": "agentless"`)) {
		t.Fatalf("served CLI lost remote posture/provenance: exit=%d err=%s output=%s", exit, cliErr.String(), cliOut.String())
	}

	if response, err := h.client.ReportJobResult(ctx, request); err != nil || !response.ReceiptRecorded {
		t.Fatalf("receipt retry: %+v %v", response, err)
	}
	if err := h.log.Replay(ctx, 0, func(event events.Event) error {
		if event.TenantID == h.tenant && (bytes.Contains(event.Data, private) || bytes.Contains(event.Data, []byte("PRIVATE KEY"))) {
			t.Fatalf("event %s exposed credential", event.Type)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !h.hasEvent(t, projections.EventSSHTrustCollectionQueued) {
		t.Fatal("missing typed immutable command")
	}
	// The restricted account executes only the fixed public profile even when
	// a stock client requests a shell command. It cannot elevate arbitrary argv.
	privatePath := filepath.Join(t.TempDir(), "reader.pk8")
	if err := os.WriteFile(privatePath, private, 0o600); err != nil {
		t.Fatal(err)
	}
	hostPublic, err := pamDockerOutput(t, 10*time.Second, "exec", host.Name, "cat", "/etc/ssh/ssh_host_ed25519_key.pub")
	if err != nil {
		t.Fatal(err)
	}
	knownPath := filepath.Join(t.TempDir(), "known_hosts")
	known := []byte(fmt.Sprintf("[127.0.0.1]:%d %s", host.Port, hostPublic))
	if err := os.WriteFile(knownPath, known, 0o600); err != nil {
		t.Fatal(err)
	}
	sshCtx, cancelSSH := context.WithTimeout(ctx, 10*time.Second)
	args := []string{"-F", "/dev/null", "-i", privatePath, "-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + knownPath, "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "BatchMode=yes", "-p", strconv.Itoa(host.Port), "trstctl_observe@127.0.0.1", "id"}
	shellOutput, shellErr := exec.CommandContext(sshCtx, "ssh", args...).Output() // #nosec G204 -- stock client against an exact owned container with strict host identity and a disposable private test key (CWE-78).
	cancelSSH()
	if shellErr != nil {
		t.Fatalf("forced-profile stock request failed: %v", shellErr)
	}
	if _, err := sshcollection.DecodeSnapshot(shellOutput); err != nil || bytes.Contains(shellOutput, []byte("uid=")) {
		t.Fatalf("requested shell escaped fixed public profile: %v", err)
	}
	forwardCtx, cancelForward := context.WithTimeout(ctx, 5*time.Second)
	forwarding := append(append([]string(nil), args[:len(args)-2]...), "-W", "127.0.0.1:22", "trstctl_observe@127.0.0.1")
	forwardOutput, forwardErr := exec.CommandContext(forwardCtx, "ssh", forwarding...).CombinedOutput() // #nosec G204 -- stock-client refusal probe forwards only toward the owned SSH test container, with the same strict host pin (CWE-78).
	cancelForward()
	if forwardErr == nil || !bytes.Contains(forwardOutput, []byte("administratively prohibited")) {
		t.Fatalf("SSH forwarding restriction was not enforced: %v %s", forwardErr, forwardOutput)
	}

	if out, err := pamDockerOutput(t, 10*time.Second, "exec", "-u", "trstctl_observe", host.Name, "sudo", "-n", "/usr/bin/id"); err == nil {
		t.Fatalf("restricted account elevated arbitrary command: %s", out)
	}
	// Every failed target stays explicit and produces no invented posture.
	config := sourceInput["config"].(sshcollection.Config)
	decodedPin, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(pin, "SHA256:"))
	if err != nil {
		t.Fatal(err)
	}
	decodedPin[0] ^= 1
	for _, scenario := range []string{"wrong-pin", "egress-denied", "unreadable-policy"} {
		if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "a227-openssh", Status: "active", Executors: &transport.ExecutorReport{Version: "a227-openssh", Kinds: []transport.ExecutorKind{{Kind: sshcollection.Destination}}}}); err != nil {
			t.Fatal(err)
		}
		badConfig := config
		badConfig.Hosts = append([]sshcollection.Host(nil), config.Hosts...)
		switch scenario {
		case "wrong-pin":
			badConfig.Hosts[0].HostKeyFingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(decodedPin)
		case "egress-denied":
			policy, err := netsec.ParseRelayEgress([]string{"192.0.2.1:22"})
			if err != nil {
				t.Fatal(err)
			}
			relay.SetEgressPolicy(policy)
			defer relay.SetEgressPolicy(nil)
		default:
			if out, err := pamDockerOutput(t, 10*time.Second, "exec", host.Name, "chmod", "0666", "/etc/trstctl/ssh-collection-v1.json"); err != nil {
				t.Fatalf("owned policy fault: %v %s", err, out)
			}
		}
		code, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/sources", token, "a227-"+scenario+"-source", map[string]any{"name": "a227-" + scenario, "kind": sshcollection.SourceKind, "config": badConfig})
		if code != 201 {
			t.Fatalf("negative source=%d %s", code, body)
		}
		var failedSource store.DiscoverySource
		if err := json.Unmarshal(body, &failedSource); err != nil {
			t.Fatal(err)
		}
		code, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/runs", token, "a227-"+scenario+"-run", map[string]any{"source_id": failedSource.ID})
		if code != 201 {
			t.Fatalf("negative queue=%d %s", code, body)
		}
		var failedRun store.DiscoveryRun
		if err := json.Unmarshal(body, &failedRun); err != nil {
			t.Fatal(err)
		}
		if n, err := relay.RunOnce(ctx, channel, nil, 1, 120); err != nil || n != 1 {
			t.Fatalf("negative executor: %d %v", n, err)
		}
		relay.SetEgressPolicy(nil)
		failed, err := h.store.GetDiscoveryRun(ctx, h.tenant, failedRun.ID)
		if err != nil || failed.Status != "failed" || failed.Discovered != 0 || failed.Failed != 1 || len(failed.TargetResults) != 1 {
			t.Fatalf("%s became success or lost target: %+v %v", scenario, failed, err)
		}
	}
	if out, err := pamDockerOutput(t, 10*time.Second, "exec", host.Name, "chmod", "0600", "/etc/trstctl/ssh-collection-v1.json"); err != nil {
		t.Fatalf("restore owned helper policy: %v %s", err, out)
	}

	// A mutable read-model row cannot invent a different remote host or public
	// effect while keeping a genuine command digest as decoration.
	if _, err := h.store.SystemPool().Exec(ctx, `UPDATE discovery_findings SET metadata=jsonb_set(metadata,'{target_address}','"forged.example:22"'::jsonb) WHERE tenant_id=$1 AND source_id=$2`, h.tenant, source.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.srv.SSHHostTrust(ctx, h.tenant); err == nil {
		t.Fatal("SQL-only target metadata was served as authenticated agentless posture")
	}
	code, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/ssh/fleet", token, nil)
	if code == http.StatusOK {
		t.Fatalf("served API hid an altered posture proof: %s", body)
	}

	if err := h.srv.proj.Rebuild(ctx, h.log); err != nil {
		t.Fatal(err)
	}
	replayed, err := h.srv.SSHHostTrust(ctx, h.tenant)
	if err != nil || len(replayed.Hosts) != 1 || replayed.Hosts[0].TargetAddress != address {
		t.Fatalf("replay lost agentless evidence: %+v %v", replayed, err)
	}
}
