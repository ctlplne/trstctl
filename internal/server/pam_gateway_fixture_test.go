// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/objectstore/s3test"
)

// gatewayFixture is a served control plane with a running access gateway, an
// sshd target that trusts the tenant SSH CA (bound to the gateway, host keys
// pinned), an embedded PostgreSQL target bound to the same gateway, recording
// storage, and the tokens the proofs act with.
type gatewayFixture struct {
	t           *testing.T
	ctx         context.Context
	h           *roleHarness
	gw          *accessgateway.Gateway
	gatewayAddr string
	gatewayLog  *lockedBuffer
	sshd        pamSSHD
	objects     *s3test.Server
	auditKey    *jose.SigningKey
	api         *httptest.Server
	dir         string
	// requester opens sessions; operator registers targets and terminates;
	// auditor reads and exports recordings.
	requester, reviewerOne, reviewerTwo, operator, auditor string
}

type gatewayFixtureOptions struct {
	recordingRetention time.Duration
}

func startGatewayFixture(t *testing.T, opts gatewayFixtureOptions) *gatewayFixture {
	t.Helper()
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	for _, tool := range []string{"ssh", "sftp"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("the stock %s client is required: %v", tool, err)
		}
	}
	pgDSN, stopPG := startPAMPostgres(t)
	t.Cleanup(stopPG)
	seedPAMPostgresTable(t, pgDSN)
	adminDSNRef := pamPostgresAdminFileRef(t, pgDSN)
	f := &gatewayFixture{t: t, objects: s3test.NewServer(t), gatewayLog: &lockedBuffer{}, dir: t.TempDir()}
	var err error
	if f.auditKey, err = jose.GenerateRSASigningKey("audit-export"); err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.gatewayAddr = raw.Addr().String()
	gatewayID := agentRowID(servedTestTenant, "role-agent")
	f.h = newRoleHarnessWithDeps(t, []string{mtls.AgentRoleGateway}, []string{relay.KindAccessGatewaySession}, func(d *Deps) {
		d.Protocols.SSH = config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}
		wirePAMPostgresProvider(d, adminDSNRef, time.Minute)
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, ExpiryInterval: 50 * time.Millisecond,
			RecordingRetention: opts.recordingRetention, Attestors: []attest.Attestor{servedPAMAttestor{}},
			PostgresTargets: []PAMPostgresTarget{{TenantID: servedTestTenant, ID: "pg-gw", ProviderID: "pam-pg-provider",
				AllowedRoles: []string{"readonly"}, GatewayAgentID: gatewayID, GatewayAddress: f.gatewayAddr}}}
		d.ArchiveObjectStore = f.objects.Open(t)
		d.AuditSigningKey = f.auditKey
	})
	h := f.h
	if _, err := h.client.Heartbeat(context.Background(), &transport.HeartbeatRequest{AgentID: h.agent, Version: "a255", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f.ctx = ctx
	startServedExternalCADispatcher(t, h.servedHarness)
	go h.srv.RunPAMSessionExpiry(ctx)

	caPub, err := h.srv.protocols.ssh.AuthorityKey()
	if err != nil {
		t.Fatal(err)
	}
	f.sshd = startPAMSSHD(t, caPub)
	var pins []string
	for _, keyType := range []string{"ed25519", "ecdsa", "rsa"} {
		out, err := pamDockerOutput(t, 15*time.Second, "exec", f.sshd.Name, "ssh-keygen", "-lf", "/etc/ssh/ssh_host_"+keyType+"_key.pub")
		fields := strings.Fields(string(out))
		if err != nil || len(fields) < 2 {
			t.Fatalf("host key fingerprint: %v %s", err, out)
		}
		pins = append(pins, fields[1])
	}
	f.requester = seedScopedTokenSubject(t, h.store, h.tenant, "pam-requester", "access:read", "access:write")
	f.reviewerOne = seedScopedTokenSubject(t, h.store, h.tenant, "pam-reviewer-one", "access:approve")
	f.reviewerTwo = seedScopedTokenSubject(t, h.store, h.tenant, "pam-reviewer-two", "access:approve")
	f.operator = seedScopedTokenSubject(t, h.store, h.tenant, "pam-operator", "access:read", "access:targets.write", "access:terminate")
	f.auditor = seedScopedTokenSubject(t, h.store, h.tenant, "pam-auditor", "access:read", "recordings:read", "recordings:export")
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", f.operator, "fixture-ssh-target", map[string]any{
		"id": "ssh-gw", "target_type": "ssh", "host": "127.0.0.1", "port": f.sshd.Port, "principals": []string{"alice"},
		"gateway_agent_id": gatewayID, "gateway_address": f.gatewayAddr, "host_key_fingerprints": pins}); status != http.StatusCreated {
		t.Fatalf("register the SSH target = %d %s", status, body)
	}
	cert, err := mtls.NewRenewingServerCertificate(h.srv.AgentCACertPEM(), []string{"127.0.0.1"}, func(csr []byte) ([]byte, error) {
		resp, err := h.client.SignGatewayServerCertificate(context.Background(), &transport.SignGatewayServerCertificateRequest{CSRDER: csr, Hosts: []string{"127.0.0.1"}})
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(resp.CertificatePEM)
		if block == nil {
			return nil, fmt.Errorf("not PEM")
		}
		return block.Bytes, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cert.Close)
	ln, err := mtls.GatewayWrapListener(raw, cert)
	if err != nil {
		t.Fatal(err)
	}
	f.gw, err = accessgateway.New(accessgateway.Config{Channel: &sshCollectionServedChannel{t: t, h: h}, Listener: ln,
		ClaimInterval: 100 * time.Millisecond, ExtendInterval: 200 * time.Millisecond,
		Logf: func(format string, args ...any) {
			_, _ = f.gatewayLog.Write([]byte(strings.TrimSpace(fmt.Sprintf(format, args...)) + "\n"))
		}})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = f.gw.Run(ctx) }()
	f.api = httptest.NewServer(h.srv.Handler())
	t.Cleanup(f.api.Close)
	return f
}

// open requests, has both reviewers approve, and opens one session.
func (f *gatewayFixture) open(key string, req map[string]any) servedPAMSessionResponse {
	f.t.Helper()
	req["reason"], req["method"] = "gateway fixture", "stub_pam"
	req["payload_base64"] = base64.StdEncoding.EncodeToString([]byte("genuine"))
	return servedPAMReviewedOpen(f.t, f.h.servedHarness, f.requester, f.reviewerOne, f.reviewerTwo, key, req)
}

func (f *gatewayFixture) openSSH(key string, ttlSeconds int) servedPAMSessionResponse {
	return f.open(key, map[string]any{"target_type": "ssh", "target_id": "ssh-gw", "role": "user", "ssh_principal": "alice", "ttl_seconds": ttlSeconds})
}

func (f *gatewayFixture) openPostgres(key string, ttlSeconds int) servedPAMSessionResponse {
	return f.open(key, map[string]any{"target_type": "postgres", "target_id": "pg-gw", "role": "readonly", "ttl_seconds": ttlSeconds})
}

// connect runs the CLI tunnel for a session until ready reports its output
// shows the tunnel is up.
func (f *gatewayFixture) connect(sessionID, ticket string, ready func(string) bool) (string, func()) {
	f.t.Helper()
	ticketFile := filepath.Join(f.dir, sessionID+"-"+strconv.FormatInt(time.Now().UnixNano(), 36)+".ticket")
	if err := os.WriteFile(ticketFile, []byte(ticket+"\n"), 0o600); err != nil {
		f.t.Fatal(err)
	}
	var out lockedBuffer
	cctx, ccancel := context.WithCancel(f.ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		cli.Run(cctx, []string{"access", "sessions", "connect", sessionID, "--ticket-file", ticketFile, "--listen", "127.0.0.1:0"},
			cli.Env{Server: f.api.URL, Token: f.requester, Tenant: f.h.tenant, HTTPClient: f.api.Client()}, strings.NewReader(""), &out, &out)
	}()
	for start := time.Now(); !ready(out.String()); time.Sleep(100 * time.Millisecond) {
		select {
		case <-done:
			f.t.Fatalf("CLI connect exited: %s (gateway: %s)", out.String(), f.gatewayLog.String())
		default:
		}
		if time.Since(start) > 30*time.Second {
			f.t.Fatalf("CLI tunnel not ready: %s", out.String())
		}
	}
	return out.String(), func() { ccancel(); <-done }
}

var fixtureSSHCommand = regexp.MustCompile(`ssh -p (\d+) -o UserKnownHostsFile=(\S+) `)

// sshTunnel opens the CLI tunnel for an SSH session and returns how a stock
// client with no credential reaches it.
func (f *gatewayFixture) sshTunnel(session servedPAMSessionResponse) (func(command ...string) *exec.Cmd, func()) {
	f.t.Helper()
	out, stop := f.connect(session.ID, session.Gateway.Ticket, fixtureSSHCommand.MatchString)
	m := fixtureSSHCommand.FindStringSubmatch(out)
	command := func(remote ...string) *exec.Cmd {
		args := []string{"-F", "/dev/null", "-o", "IdentitiesOnly=yes", "-o", "IdentityFile=/dev/null", "-o", "IdentityAgent=none",
			"-o", "BatchMode=yes", "-o", "UserKnownHostsFile=" + m[2], "-o", "StrictHostKeyChecking=yes", "-p", m[1], "client@127.0.0.1"}
		return exec.CommandContext(f.ctx, "ssh", append(args, remote...)...) // #nosec G204 -- the stock ssh client against the test's own tunnel (CWE-78)
	}
	return command, stop
}

var fixturePostgresListen = regexp.MustCompile(`connect your client to (127\.0\.0\.1:\d+)`)

// postgresTunnel opens the CLI tunnel for a PostgreSQL session and returns
// the loopback address a stock client connects to.
func (f *gatewayFixture) postgresTunnel(session servedPAMSessionResponse) (string, func()) {
	f.t.Helper()
	out, stop := f.connect(session.ID, session.Gateway.Ticket, fixturePostgresListen.MatchString)
	return fixturePostgresListen.FindStringSubmatch(out)[1], stop
}

// sessionRead reads a session as the requester sees it.
func (f *gatewayFixture) sessionRead(id string) map[string]any {
	f.t.Helper()
	status, body := secretsReq(f.t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+id, f.requester, nil)
	if status != http.StatusOK {
		f.t.Fatalf("read session %s = %d %s", id, status, body)
	}
	return decodeJSONMap(f.t, body)
}
