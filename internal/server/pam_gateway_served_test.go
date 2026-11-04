// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuffer) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// TestServedGatewayKeepsThePostgresCredentialFromTheClientA254 is A254 part 1:
// a PostgreSQL target bound to a gateway-role agent. The approved open returns
// a ticket and the gateway's identity, never a credential; the gateway claims
// the session as a job and redeems the credential into its own memory; the
// trstctl CLI tunnels a stock PostgreSQL client to it over TLS verified
// against the gateway's agent certificate; the client signs in with no
// password and runs as the session's login. The upstream password appears in
// no response, CLI output or ticket file. A connection with a wrong ticket, or
// for a session the gateway does not hold, is refused at the gateway; a
// revocation recalls the session's job, so the gateway ends the live
// connection.
func TestServedGatewayKeepsThePostgresCredentialFromTheClientA254(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	seedPAMPostgresTable(t, pgDSN)
	adminDSNRef := pamPostgresAdminFileRef(t, pgDSN)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gatewayAddr := raw.Addr().String()
	gatewayID := agentRowID(servedTestTenant, "role-agent")
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleGateway}, []string{relay.KindAccessGatewaySession}, func(d *Deps) {
		wirePAMPostgresProvider(d, adminDSNRef, time.Minute)
		d.PAM = PAMConfig{
			Enabled: true, DefaultTTL: 30 * time.Second, MaxTTL: time.Minute, ExpiryInterval: 50 * time.Millisecond,
			Attestors: []attest.Attestor{servedPAMAttestor{}},
			PostgresTargets: []PAMPostgresTarget{{TenantID: servedTestTenant, ID: "pg-gw", ProviderID: "pam-pg-provider",
				AllowedRoles: []string{"readonly"}, GatewayAgentID: gatewayID, GatewayAddress: gatewayAddr}},
		}
	})
	if h.tenant != servedTestTenant {
		t.Fatalf("role harness tenant %s", h.tenant)
	}
	startServedExternalCADispatcher(t, h.servedHarness)
	// The gateway's first heartbeat registers it, as a running agent's does.
	if _, err := h.client.Heartbeat(context.Background(), &transport.HeartbeatRequest{AgentID: h.agent, Version: "a254", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	// The gateway's serving certificate: signed by the agent CA for the host
	// its binding declares, naming the gateway agent's SPIFFE ID.
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
	if _, err := h.client.SignGatewayServerCertificate(context.Background(), &transport.SignGatewayServerCertificateRequest{
		CSRDER: []byte("x"), Hosts: []string{"db.example.test"}}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a host no binding declares was signed: %v", err)
	}
	// The signing is on the record: the production event log refuses an
	// event type with no privacy schema, so this fails if it was dropped.
	if !h.hasEvent(t, "agent.gateway.server_certificate_signed") {
		t.Fatal("the gateway serving certificate's signing was not recorded")
	}
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = gw.Run(ctx) }()
	go h.srv.RunPAMSessionExpiry(ctx)

	requester := seedScopedTokenSubject(t, h.store, h.tenant, "pam-requester", "access:read", "access:write")
	reviewerOne := seedScopedTokenSubject(t, h.store, h.tenant, "pam-reviewer-one", "access:approve")
	reviewerTwo := seedScopedTokenSubject(t, h.store, h.tenant, "pam-reviewer-two", "access:approve")
	issued := servedPAMReviewedOpen(t, h.servedHarness, requester, reviewerOne, reviewerTwo, "a254-gateway", map[string]any{
		"target_type": "postgres", "target_id": "pg-gw", "role": "readonly",
		"reason": "gateway proof", "method": "stub_pam",
		"payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")), "ttl_seconds": 30,
	})
	if issued.Postgres != nil || issued.Delivery != "gateway" || issued.Gateway == nil || issued.Gateway.Ticket == "" ||
		issued.Gateway.Address != gatewayAddr || issued.Gateway.AgentID != gatewayID || issued.Gateway.CAPEM == "" ||
		issued.Gateway.SPIFFEID != mtls.AgentSPIFFEID(h.tenant, h.agent) {
		t.Fatalf("gateway open = %+v gateway=%+v", issued, issued.Gateway)
	}
	dsn, err := h.srv.pam.gatewaySessionCredential(ctx, h.tenant, issued.ID)
	if err != nil {
		t.Fatalf("reopen the session credential: %v", err)
	}
	parsed, err := url.Parse(string(dsn))
	if err != nil {
		t.Fatal(err)
	}
	password, _ := parsed.User.Password()
	login := parsed.User.Username()
	if password == "" || login == "" {
		t.Fatalf("session DSN has no login")
	}

	api := httptest.NewServer(h.srv.Handler())
	defer api.Close()
	dir := t.TempDir()
	connect := func(sessionID, ticket string) (string, *lockedBuffer, func()) {
		t.Helper()
		ticketFile := filepath.Join(dir, sessionID+"-"+strings.ReplaceAll(ticket, "/", "_")[:4]+".ticket")
		if err := os.WriteFile(ticketFile, []byte(ticket+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		probe, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		local := probe.Addr().String()
		_ = probe.Close()
		var out lockedBuffer
		cctx, ccancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			cli.Run(cctx, []string{"access", "sessions", "connect", sessionID, "--ticket-file", ticketFile, "--listen", local},
				cli.Env{Server: api.URL, Token: requester, Tenant: h.tenant, HTTPClient: api.Client()}, strings.NewReader(""), &out, &out)
		}()
		for start := time.Now(); ; time.Sleep(100 * time.Millisecond) {
			if c, err := net.DialTimeout("tcp", local, 200*time.Millisecond); err == nil {
				_ = c.Close()
				break
			}
			select {
			case <-done:
				t.Fatalf("CLI connect exited: %s", out.String())
			default:
			}
			if time.Since(start) > 20*time.Second {
				t.Fatalf("CLI tunnel not listening: %s", out.String())
			}
		}
		return local, &out, func() { ccancel(); <-done }
	}
	// A stock client: no password, any user — the gateway signs in.
	pgConnect := func(local string) (*pgconn.PgConn, error) {
		cctx, ccancel := context.WithTimeout(ctx, 20*time.Second)
		defer ccancel()
		return pgconn.Connect(cctx, "postgres://client-without-credential@"+local+"/postgres?sslmode=disable&connect_timeout=15")
	}

	local, cliOut, stopCLI := connect(issued.ID, issued.Gateway.Ticket)
	conn, err := pgConnect(local)
	if err != nil {
		t.Fatalf("stock client through the gateway: %v (cli: %s; gateway: %s)", err, cliOut.String(), gatewayLog.String())
	}
	result := conn.ExecParams(ctx, "SELECT current_user", nil, nil, nil, nil).Read()
	if result.Err != nil || len(result.Rows) != 1 || string(result.Rows[0][0]) != login {
		t.Fatalf("query through the gateway = %+v err=%v, want current_user %s", result.Rows, result.Err, login)
	}

	// The credential is nowhere the client side can see.
	status, sessionBody := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+issued.ID, requester, nil)
	if status != http.StatusOK {
		t.Fatalf("read session = %d %s", status, sessionBody)
	}
	ticketFiles, _ := filepath.Glob(filepath.Join(dir, "*.ticket"))
	for name, text := range map[string]string{"session read": string(sessionBody), "cli output": cliOut.String(), "gateway log": gatewayLog.String()} {
		if strings.Contains(text, password) || strings.Contains(text, string(dsn)) {
			t.Fatalf("the upstream credential reached the %s", name)
		}
	}
	for _, f := range ticketFiles {
		raw, _ := os.ReadFile(f) // #nosec G304 -- the test's own temporary files (CWE-22)
		if bytes.Contains(raw, []byte(password)) {
			t.Fatal("the upstream credential reached a ticket file")
		}
	}
	if bytes.Contains(sessionBody, []byte(issued.Gateway.Ticket)) {
		t.Fatal("a session read returned the ticket again")
	}

	// Refused at the gateway: a wrong ticket, and a session it does not hold.
	wrong, wrongOut, stopWrong := connect(issued.ID, "not-the-ticket-for-this-session-00000000000")
	if c, err := pgConnect(wrong); err == nil {
		_ = c.Close(ctx)
		t.Fatal("a wrong ticket reached the database")
	}
	stopWrong()
	if !strings.Contains(wrongOut.String(), "ticket refused") {
		t.Fatalf("wrong ticket CLI output = %s", wrongOut.String())
	}
	// Refused at the target: straight to the database as the session's
	// login, the client has no password it accepts.
	targetURL, err := url.Parse(pgDSN)
	if err != nil {
		t.Fatal(err)
	}
	directCtx, directCancel := context.WithTimeout(ctx, 20*time.Second)
	if c, err := pgconn.Connect(directCtx, "postgres://"+login+"@"+targetURL.Host+"/postgres?sslmode=disable&connect_timeout=15"); err == nil {
		_ = c.Close(ctx)
		directCancel()
		t.Fatal("a straight connection to the database signed in without the session's password")
	}
	directCancel()

	// Revocation recalls the session's job: the gateway ends the live
	// connection and admits no new one.
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+issued.ID+"/revoke", requester,
		"a254-revoke", map[string]any{"reason": "gateway proof"})
	if status != http.StatusAccepted {
		t.Fatalf("revoke = %d %s", status, body)
	}
	a201Await(t, "gateway ends the revoked session", func() bool {
		for _, id := range gw.Sessions() {
			if id == issued.ID {
				return false
			}
		}
		return true
	})
	if r := conn.ExecParams(ctx, "SELECT 1", nil, nil, nil, nil).Read(); r.Err == nil {
		t.Fatal("the revoked session's live connection still runs queries")
	}
	if c, err := pgConnect(local); err == nil {
		_ = c.Close(ctx)
		t.Fatal("the revoked session admitted a new connection")
	}
	stopCLI()
	if !strings.Contains(gatewayLog.String(), "ended: recalled") {
		t.Fatalf("gateway log = %s", gatewayLog.String())
	}
	var check struct {
		Status string `json:"status"`
	}
	a201Await(t, "session settles revoked", func() bool {
		_, b := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+issued.ID, requester, nil)
		return json.Unmarshal(b, &check) == nil && check.Status == "revoked"
	})
}
