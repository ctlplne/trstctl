// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// SignJobSSHKey lets the served gateway certify its per-session SSH keys over
// the same channel it claims on.
func (c *sshCollectionServedChannel) SignJobSSHKey(ctx context.Context, id int64, attempt int, publicKey []byte) ([]byte, error) {
	response, err := c.h.client.SignJobSSHKey(ctx, &transport.SignJobSSHKeyRequest{JobID: id, Attempt: attempt, PublicKey: publicKey})
	if err != nil {
		return nil, err
	}
	return response.Certificate, nil
}

// TestServedGatewayKeepsTheSSHCredentialFromTheClientA254 is A254 part 2: an
// SSH target bound to a gateway-role agent, with the target's host keys
// pinned. The approved open returns a ticket, never a certificate; the gateway
// generates the session's key itself and has the tenant SSH CA certify it for
// the job it holds; stock ssh, holding no key, no certificate and no agent,
// runs as the session's principal through the trstctl CLI's tunnel. Each
// refusal is made where it is claimed: a principal the target does not list
// and a requester key at the open, another tenant at the API, an expired
// session at the gateway, a straight connection at the target. A control-plane
// restart mid-session keeps the live connection, the one session, its one job
// and its deadline. A revocation puts the session's key ID on the KRL, and the
// gateway ends the live connection.
func TestServedGatewayKeepsTheSSHCredentialFromTheClientA254(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skipf("the stock ssh client is required: %v", err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gatewayAddr := raw.Addr().String()
	gatewayID := agentRowID(servedTestTenant, "role-agent")
	var deps Deps
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleGateway}, []string{relay.KindAccessGatewaySession}, func(d *Deps) {
		d.Protocols.SSH = config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, ExpiryInterval: 50 * time.Millisecond,
			Attestors: []attest.Attestor{servedPAMAttestor{}}}
		deps = *d
	})
	if h.tenant != servedTestTenant {
		t.Fatalf("role harness tenant %s", h.tenant)
	}
	if _, err := h.client.Heartbeat(context.Background(), &transport.HeartbeatRequest{AgentID: h.agent, Version: "a254", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	workerCtx, stopWorker := context.WithCancel(ctx)
	go h.srv.RunPAMSessionExpiry(workerCtx)

	// The target: a stock sshd that trusts the tenant SSH CA for alice, its
	// host keys pinned on the target registration.
	caPub, err := h.srv.protocols.ssh.AuthorityKey()
	if err != nil {
		t.Fatalf("ssh authority key: %v", err)
	}
	sshd := startPAMSSHD(t, caPub)
	var pins []string
	for _, keyType := range []string{"ed25519", "ecdsa", "rsa"} {
		out, err := pamDockerOutput(t, 15*time.Second, "exec", sshd.Name, "ssh-keygen", "-lf", "/etc/ssh/ssh_host_"+keyType+"_key.pub")
		fields := strings.Fields(string(out))
		if err != nil || len(fields) < 2 || !strings.HasPrefix(fields[1], "SHA256:") {
			t.Fatalf("sshd %s host key fingerprint: %v %s", keyType, err, out)
		}
		pins = append(pins, fields[1])
	}
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "pam-operator", "access:read", "access:targets.write")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "pam-requester", "access:read", "access:write")
	reviewerOne := seedScopedTokenSubject(t, h.store, h.tenant, "pam-reviewer-one", "access:approve")
	reviewerTwo := seedScopedTokenSubject(t, h.store, h.tenant, "pam-reviewer-two", "access:approve")
	target := map[string]any{"id": "ssh-gw", "target_type": "ssh", "host": "127.0.0.1", "port": sshd.Port,
		"principals": []string{"alice"}, "gateway_agent_id": gatewayID, "gateway_address": gatewayAddr}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", operator, "a254-target-unpinned", target); status != http.StatusUnprocessableEntity {
		t.Fatalf("a gateway-bound SSH target with no host key pin = %d %s, want 422", status, body)
	}
	target["host_key_fingerprints"] = pins
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", operator, "a254-target", target); status != http.StatusCreated {
		t.Fatalf("register the gateway-bound SSH target = %d %s", status, body)
	}

	// The gateway: its serving certificate from the agent CA, and its runtime.
	cert, err := mtls.NewRenewingServerCertificate(h.srv.AgentCACertPEM(), []string{"127.0.0.1"}, func(csr []byte) ([]byte, error) {
		resp, err := h.client.SignGatewayServerCertificate(context.Background(), &transport.SignGatewayServerCertificateRequest{CSRDER: csr, Hosts: []string{"127.0.0.1"}})
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(resp.CertificatePEM)
		if block == nil {
			return nil, fmt.Errorf("gateway certificate is not PEM")
		}
		return block.Bytes, nil
	})
	if err != nil {
		t.Fatalf("gateway serving certificate: %v", err)
	}
	t.Cleanup(cert.Close)
	ln, err := mtls.GatewayWrapListener(raw, cert)
	if err != nil {
		t.Fatal(err)
	}
	var gatewayLog lockedBuffer
	gw, err := accessgateway.New(accessgateway.Config{Channel: &sshCollectionServedChannel{t: t, h: h}, Listener: ln,
		ClaimInterval: 100 * time.Millisecond, ExtendInterval: 200 * time.Millisecond,
		Logf: func(format string, args ...any) {
			_, _ = gatewayLog.Write([]byte(strings.TrimSpace(fmt.Sprintf(format, args...)) + "\n"))
		}})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gw.Run(ctx) }()

	request := func(extra map[string]any) map[string]any {
		out := map[string]any{"target_type": "ssh", "target_id": "ssh-gw", "role": "user", "ssh_principal": "alice",
			"reason": "gateway ssh proof", "method": "stub_pam",
			"payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")), "ttl_seconds": 120}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	// Refused at the request: a key of the requester's own for a target the
	// gateway serves (the gateway certifies a key of its own).
	keyed := request(map[string]any{"ssh_public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBl7l0Yh0n1T6CPRQbNbqyWZ3JeFQ8ZtGq2iWJr6nMbD requester"})
	keyed["request_id"] = uuid.NewString()
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/session-requests", requester, "a254-keyed", keyed); status != http.StatusUnprocessableEntity {
		t.Fatalf("a requester key for a gateway target = %d %s, want 422", status, body)
	}
	// Refused at the open, even after both reviews: a principal the target
	// does not list.
	unlisted := request(map[string]any{"ssh_principal": "root"})
	unlisted["request_id"] = uuid.NewString()
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/session-requests", requester, "a254-root", unlisted)
	if status == http.StatusAccepted {
		var pending struct {
			ApprovalRequestID string `json:"approval_request_id"`
			IntentDigest      string `json:"intent_digest"`
		}
		if err := json.Unmarshal(body, &pending); err != nil {
			t.Fatal(err)
		}
		for i, reviewer := range []string{reviewerOne, reviewerTwo} {
			if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+pending.ApprovalRequestID+"/approvals",
				reviewer, fmt.Sprintf("a254-root-review-%d", i), map[string]any{"intent_digest": pending.IntentDigest}); status != http.StatusOK {
				t.Fatalf("review %d = %d %s", i, status, body)
			}
		}
		unlisted["approval_request_id"], unlisted["intent_digest"] = pending.ApprovalRequestID, pending.IntentDigest
		status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions", requester, "a254-root-open", unlisted)
	}
	if status < 400 {
		t.Fatalf("an unlisted principal opened a session: %d %s", status, body)
	}
	issuedBefore := pamEventCount(t, h.servedHarness, "ssh.cert.issued")
	issued := servedPAMReviewedOpen(t, h.servedHarness, requester, reviewerOne, reviewerTwo, "a254-ssh", request(nil))
	if issued.SSH != nil || issued.Delivery != "gateway" || issued.Gateway == nil || issued.Gateway.Ticket == "" ||
		issued.Gateway.Address != gatewayAddr || issued.Gateway.AgentID != gatewayID ||
		issued.Gateway.SPIFFEID != mtls.AgentSPIFFEID(h.tenant, h.agent) {
		t.Fatalf("gateway ssh open = %+v gateway=%+v", issued, issued.Gateway)
	}
	if pamEventCount(t, h.servedHarness, "ssh.cert.issued") != issuedBefore {
		t.Fatal("the open signed a certificate; only the gateway's claim may")
	}

	var apiHandler atomic.Value
	apiHandler.Store(h.srv.Handler())
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiHandler.Load().(http.Handler).ServeHTTP(w, r)
	}))
	defer api.Close()
	dir := t.TempDir()
	sshCommand := regexp.MustCompile(`ssh -p (\d+) -o UserKnownHostsFile=(\S+) -o StrictHostKeyChecking=yes 127\.0\.0\.1`)
	type tunnel struct {
		port       int
		knownHosts string
		out        *lockedBuffer
		stop       func()
	}
	connect := func(sessionID, ticket string) tunnel {
		t.Helper()
		ticketFile := filepath.Join(dir, sessionID+"-"+strconv.FormatInt(time.Now().UnixNano(), 36)+".ticket")
		if err := os.WriteFile(ticketFile, []byte(ticket+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		var out lockedBuffer
		cctx, ccancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			cli.Run(cctx, []string{"access", "sessions", "connect", sessionID, "--ticket-file", ticketFile, "--listen", "127.0.0.1:0"},
				cli.Env{Server: api.URL, Token: requester, Tenant: h.tenant, HTTPClient: api.Client()}, strings.NewReader(""), &out, &out)
		}()
		for start := time.Now(); ; time.Sleep(100 * time.Millisecond) {
			if m := sshCommand.FindStringSubmatch(out.String()); m != nil {
				port, _ := strconv.Atoi(m[1])
				return tunnel{port: port, knownHosts: m[2], out: &out, stop: func() { ccancel(); <-done }}
			}
			select {
			case <-done:
				t.Fatalf("CLI connect exited: %s (gateway: %s)", out.String(), gatewayLog.String())
			default:
			}
			if time.Since(start) > 30*time.Second {
				t.Fatalf("CLI tunnel not ready: %s (gateway: %s)", out.String(), gatewayLog.String())
			}
		}
	}
	// A stock client with nothing to sign in with: no identity, no agent, no
	// configuration; it trusts only the host key the CLI wrote.
	sshArgs := func(tn tunnel, command ...string) []string {
		return append([]string{"-F", "/dev/null", "-o", "IdentitiesOnly=yes", "-o", "IdentityFile=/dev/null", "-o", "IdentityAgent=none",
			"-o", "BatchMode=yes", "-o", "ConnectTimeout=20", "-o", "UserKnownHostsFile=" + tn.knownHosts, "-o", "StrictHostKeyChecking=yes",
			"-p", strconv.Itoa(tn.port), "client-without-credential@127.0.0.1"}, command...)
	}
	runSSH := func(tn tunnel, command string) (string, error) {
		cctx, ccancel := context.WithTimeout(ctx, 60*time.Second)
		defer ccancel()
		out, err := exec.CommandContext(cctx, "ssh", sshArgs(tn, command)...).CombinedOutput() // #nosec G204 -- the stock ssh client against the test's own tunnel (CWE-78)
		return strings.TrimSpace(string(out)), err
	}

	tn := connect(issued.ID, issued.Gateway.Ticket)
	if out, err := runSSH(tn, "id -un"); err != nil || out != "alice" {
		logs, _ := pamDockerOutput(t, 15*time.Second, "logs", sshd.Name)
		t.Fatalf("stock ssh through the gateway = %q, %v (cli: %s; gateway: %s; sshd: %s)", out, err, tn.out.String(), gatewayLog.String(), logs)
	}
	if pamEventCount(t, h.servedHarness, "ssh.cert.issued") != issuedBefore+1 {
		t.Fatal("the gateway's session key was not certified exactly once")
	}
	if !h.hasEvent(t, "agent.gateway.session_key_certified") {
		t.Fatal("the session key certification was not recorded")
	}
	// No SSH credential anywhere on the client side.
	status, sessionBody := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+issued.ID, requester, nil)
	if status != http.StatusOK {
		t.Fatalf("read session = %d %s", status, sessionBody)
	}
	clientSide := map[string]string{"session read": string(sessionBody), "cli output": tn.out.String()}
	files, _ := filepath.Glob(filepath.Join(dir, "*"))
	for _, f := range files {
		raw, _ := os.ReadFile(f) // #nosec G304 -- the test's own temporary files (CWE-22)
		clientSide[filepath.Base(f)] = string(raw)
	}
	for name, text := range clientSide {
		if strings.Contains(text, "-cert-v01@openssh.com") || strings.Contains(text, "PRIVATE KEY") {
			t.Fatalf("an SSH credential reached the %s", name)
		}
	}
	// Refused at the target: straight to sshd as alice, the client has
	// nothing it accepts (the host key is accepted here so the refusal shown
	// is the target's authentication, not host verification).
	directCtx, directCancel := context.WithTimeout(ctx, 60*time.Second)
	directOut, err := exec.CommandContext(directCtx, "ssh", "-F", "/dev/null", "-o", "IdentitiesOnly=yes", "-o", "IdentityFile=/dev/null", // #nosec G204 -- the stock ssh client against the test's own sshd (CWE-78)
		"-o", "IdentityAgent=none", "-o", "BatchMode=yes", "-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no",
		"-p", strconv.Itoa(sshd.Port), "alice@127.0.0.1", "id -un").CombinedOutput()
	directCancel()
	if err == nil || !strings.Contains(string(directOut), "Permission denied") {
		t.Fatalf("a straight connection to the target = %q, %v, want refused", directOut, err)
	}
	// Refused at the API: another tenant cannot read the session or bind this
	// tenant's gateway to a target of its own.
	otherTenant := uuid.NewString()
	registerServedTenantID(t, h.servedHarness, otherTenant, "A254 other tenant")
	other := seedScopedTokenSubject(t, h.store, otherTenant, "other-operator", "access:read", "access:targets.write")
	if status, _ := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+issued.ID, other, nil); status != http.StatusNotFound {
		t.Fatalf("another tenant read the session: %d", status)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", other, "a254-other-target", target); status != http.StatusUnprocessableEntity {
		t.Fatalf("another tenant bound this tenant's gateway = %d %s", status, body)
	}

	// A live session through a control-plane restart.
	live := exec.CommandContext(ctx, "ssh", sshArgs(tn, `while read line; do echo "got $line"; done`)...) // #nosec G204 -- the stock ssh client against the test's own tunnel (CWE-78)
	stdin, err := live.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := live.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := live.Start(); err != nil {
		t.Fatal(err)
	}
	liveDone := make(chan error, 1)
	go func() { liveDone <- live.Wait() }()
	lines := bufio.NewScanner(stdout)
	echo := func(word string) {
		t.Helper()
		if _, err := io.WriteString(stdin, word+"\n"); err != nil {
			t.Fatalf("write to the live session: %v", err)
		}
		got := make(chan string, 1)
		go func() {
			if lines.Scan() {
				got <- lines.Text()
			}
			close(got)
		}()
		select {
		case line := <-got:
			if line != "got "+word {
				t.Fatalf("live session answered %q, want %q", line, "got "+word)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("live session did not answer %q (gateway: %s)", word, gatewayLog.String())
		}
	}
	echo("before")
	sessionState := func() (string, time.Time) {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+issued.ID, requester, nil)
		var read struct {
			Status    string    `json:"status"`
			ExpiresAt time.Time `json:"expires_at"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &read) != nil {
			t.Fatalf("read session = %d %s", status, body)
		}
		return read.Status, read.ExpiresAt
	}
	startedFor := func() int {
		t.Helper()
		n := 0
		if err := h.log.Replay(context.Background(), 0, func(e events.Event) error {
			if e.Type == projections.EventPAMSessionStarted && e.TenantID == h.tenant && strings.Contains(string(e.Data), issued.ID) {
				n++
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	jobsFor := func() int {
		t.Helper()
		var n int
		if err := h.store.SystemPool().QueryRow(context.Background(),
			`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`, h.tenant, accessgateway.JobKey(issued.ID)).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	_, deadlineBefore := sessionState()
	if startedFor() != 1 || jobsFor() != 1 {
		t.Fatalf("before the restart: %d started events, %d jobs", startedFor(), jobsFor())
	}
	leaseUntil := func() time.Time {
		t.Helper()
		var until time.Time
		if err := h.store.SystemPool().QueryRow(context.Background(),
			`SELECT claim_expires_at FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`, h.tenant, accessgateway.JobKey(issued.ID)).Scan(&until); err != nil {
			t.Fatal(err)
		}
		return until
	}
	leaseBefore := leaseUntil()

	// The restart: the old process stops serving its channel, API and
	// workers; a new one is built from the same store, event log and signer
	// and serves the same channel address.
	h.stopChannel()
	stopWorker()
	rebuilt, err := Build(context.Background(), deps)
	if err != nil {
		t.Fatalf("restart: build: %v", err)
	}
	cleanupServedServer(t, rebuilt)
	var channel net.Listener
	for start := time.Now(); ; time.Sleep(50 * time.Millisecond) {
		if channel, err = net.Listen("tcp", h.channelAddr); err == nil {
			break
		}
		if time.Since(start) > 10*time.Second {
			t.Fatalf("restart: listen on %s again: %v", h.channelAddr, err)
		}
	}
	channelCtx, stopNewChannel := context.WithCancel(ctx)
	channelDone := make(chan struct{})
	go func() { defer close(channelDone); rebuilt.serveAgentChannel(channelCtx, channel) }()
	t.Cleanup(func() { stopNewChannel(); <-channelDone })
	h.srv = rebuilt
	h.ts = httptest.NewServer(rebuilt.Handler())
	defer h.ts.Close()
	apiHandler.Store(rebuilt.Handler())
	go rebuilt.RunPAMSessionExpiry(ctx)

	echo("during the restart") // the live connection never needed the control plane
	// The gateway's lease extensions reach the new process (the lease moves
	// past where the old process left it) and the session is never ended.
	a201Await(t, "the gateway extends its lease against the restarted control plane", func() bool {
		return leaseUntil().After(leaseBefore.Add(time.Second))
	})
	if strings.Contains(gatewayLog.String(), "ended:") || !slices.Contains(gw.Sessions(), issued.ID) || jobsFor() != 1 {
		t.Fatalf("the restart disturbed the session: held=%v jobs=%d gateway: %s", gw.Sessions(), jobsFor(), gatewayLog.String())
	}
	echo("after")
	statusAfter, deadlineAfter := sessionState()
	if statusAfter != "active" || !deadlineAfter.Equal(deadlineBefore) {
		t.Fatalf("after the restart the session is %s until %s, want active until %s", statusAfter, deadlineAfter, deadlineBefore)
	}
	if startedFor() != 1 || jobsFor() != 1 {
		t.Fatalf("after the restart: %d started events, %d jobs, want one of each", startedFor(), jobsFor())
	}
	tn2 := connect(issued.ID, issued.Gateway.Ticket)
	if out, err := runSSH(tn2, "id -un"); err != nil || out != "alice" {
		t.Fatalf("a new connection after the restart = %q, %v (gateway: %s)", out, err, gatewayLog.String())
	}

	// Refused at the gateway: a session past its deadline.
	short := servedPAMReviewedOpen(t, h.servedHarness, requester, reviewerOne, reviewerTwo, "a254-ssh-short", request(map[string]any{"ttl_seconds": 3}))
	a201Await(t, "the short session expires", func() bool {
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+short.ID, requester, nil)
		return status == http.StatusOK && strings.Contains(string(body), `"status":"expired"`)
	})
	expiredConn, err := mtls.GatewayDial(ctx, gatewayAddr, []byte(short.Gateway.CAPEM), short.Gateway.SPIFFEID)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(expiredConn, "%s %s %s\n", accessgateway.Preface, short.ID, short.Gateway.Ticket)
	answer, _ := bufio.NewReader(expiredConn).ReadString('\n')
	_ = expiredConn.Close()
	if !strings.HasPrefix(answer, "DENY ") {
		t.Fatalf("an expired session's ticket was admitted: %q", answer)
	}

	// Revocation: the KRL holds the session's key ID, which every certificate
	// the gateway was given for it carries, and the gateway ends the live
	// connection.
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+issued.ID+"/revoke", requester,
		"a254-ssh-revoke", map[string]any{"reason": "gateway ssh proof"})
	if status != http.StatusAccepted {
		t.Fatalf("revoke = %d %s", status, body)
	}
	a201Await(t, "the revoked session's key ID on the KRL", func() bool {
		krl := rebuilt.pam.sshProtocol
		krl.syncMu.Lock()
		defer krl.syncMu.Unlock()
		return krl.krl.IsRevoked(0, "pam:"+issued.ID)
	})
	a201Await(t, "the gateway ends the revoked session", func() bool { return !slices.Contains(gw.Sessions(), issued.ID) })
	select {
	case <-liveDone:
	case <-time.After(30 * time.Second):
		t.Fatal("the revoked session's live connection is still open")
	}
	if out, err := runSSH(tn2, "id -un"); err == nil {
		t.Fatalf("the revoked session admitted a new connection: %q", out)
	}
	tn.stop()
	tn2.stop()
	if !strings.Contains(gatewayLog.String(), "ended: recalled") {
		t.Fatalf("gateway log = %s", gatewayLog.String())
	}
}
