// SPDX-License-Identifier: BUSL-1.1

package server

import (
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
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/crypto/certtest"
	"trstctl.com/trstctl/internal/crypto/mtls"
	embeddedpostgres "trstctl.com/trstctl/third_party/embedded-postgres"
)

// privateCAPostgres is an embedded PostgreSQL that accepts only TLS over TCP,
// serving a certificate for localhost from a private CA no system trusts.
type privateCAPostgres struct {
	// adminDSN verifies the server against caFile (sslmode=verify-full), as
	// an operator's administrator DSN names its root file on the control
	// plane's host.
	adminDSN, caFile string
}

func startPAMPostgresPrivateCA(t *testing.T) privateCAPostgres {
	t.Helper()
	caPEM, certPEM, keyPEM, err := certtest.PrivateCAServer("localhost")
	if err != nil {
		t.Fatal(err)
	}
	tlsDir := t.TempDir()
	pg := privateCAPostgres{caFile: filepath.Join(tlsDir, "root.crt")}
	certFile, keyFile := filepath.Join(tlsDir, "server.crt"), filepath.Join(tlsDir, "server.key")
	for path, body := range map[string][]byte{pg.caFile: caPEM, certFile: certPEM, keyFile: keyPEM} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	port := freePAMPort(t)
	dir, err := os.MkdirTemp("", "trstctl-pam-pgca-*")
	if err != nil {
		t.Fatal(err)
	}
	bin, runtime, data := filepath.Join(dir, "bin"), filepath.Join(dir, "runtime"), filepath.Join(dir, "data")
	for _, path := range []string{bin, runtime, data} {
		if err := os.MkdirAll(path, 0o755); err != nil { // #nosec G301 -- fixture tree in a test tempdir; the mode is part of the fixture (CWE-276)
			t.Fatal(err)
		}
	}
	db := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Username("postgres").Password("postgres").Database("postgres").
		Port(uint32(port)).RuntimePath(runtime).DataPath(data).BinariesPath(bin). // #nosec G115 -- bounded fixture/corpus value packing inside a test (CWE-190)
		StartParameters(map[string]string{"ssl": "on", "ssl_cert_file": certFile, "ssl_key_file": keyFile}))
	if err := db.Start(); err != nil {
		_ = os.RemoveAll(dir)
		fmt.Fprintln(os.Stderr, "embedded postgres start:", err)
		t.Skip("embedded postgres unavailable")
	}
	t.Cleanup(func() {
		_ = db.Stop()
		_ = os.RemoveAll(dir)
	})
	// From here on the database refuses every TCP connection that is not TLS.
	hbaPath := filepath.Join(data, "pg_hba.conf")
	hba, err := os.ReadFile(hbaPath) // #nosec G304 -- the fixture's own data directory (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hbaPath, append([]byte("hostnossl all all all reject\n"), hba...), 0o600); err != nil { // #nosec G703 -- the fixture's own data directory (CWE-22)
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres?sslmode=disable", port))
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.Exec(ctx, "SELECT pg_reload_conf()")
	_ = conn.Close(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pg.adminDSN = fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres?sslmode=verify-full&sslrootcert=%s", port, pg.caFile)
	return pg
}

// TestServedGatewaySignsInToAPrivateCAPostgresWithoutARootFileA256L1 is
// A256-L1. A PostgreSQL target that accepts only TLS, behind a private CA;
// its provider's administrator DSN verifies it against a root file on the
// control plane's host, and the session's credential names the same path.
// The gateway's host has no such file. The control plane reads the CA and
// carries it with the session's job, so the gateway signs in, verifies the
// database against it, and a stock client runs as the session's login over
// the gateway's TLS upstream. A revocation still recalls the session.
func TestServedGatewaySignsInToAPrivateCAPostgresWithoutARootFileA256L1(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	pg := startPAMPostgresPrivateCA(t)
	seedPAMPostgresTable(t, pg.adminDSN)
	adminDSNRef := pamPostgresAdminFileRef(t, pg.adminDSN)
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
			PostgresTargets: []PAMPostgresTarget{{TenantID: servedTestTenant, ID: "pg-private-ca", ProviderID: "pam-pg-provider",
				AllowedRoles: []string{"readonly"}, GatewayAgentID: gatewayID, GatewayAddress: gatewayAddr}},
		}
	})
	startServedExternalCADispatcher(t, h.servedHarness)
	if _, err := h.client.Heartbeat(context.Background(), &transport.HeartbeatRequest{AgentID: h.agent, Version: "a256-l1", Status: "active"}); err != nil {
		t.Fatal(err)
	}
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = gw.Run(ctx) }()
	go h.srv.RunPAMSessionExpiry(ctx)

	requester := seedScopedTokenSubject(t, h.store, h.tenant, "pam-requester", "access:read", "access:write")
	reviewerOne := seedScopedTokenSubject(t, h.store, h.tenant, "pam-reviewer-one", "access:approve")
	reviewerTwo := seedScopedTokenSubject(t, h.store, h.tenant, "pam-reviewer-two", "access:approve")
	issued := servedPAMReviewedOpen(t, h.servedHarness, requester, reviewerOne, reviewerTwo, "a256l1-private-ca", map[string]any{
		"target_type": "postgres", "target_id": "pg-private-ca", "role": "readonly",
		"reason": "private CA proof", "method": "stub_pam",
		"payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")), "ttl_seconds": 30,
	})
	if issued.Delivery != "gateway" || issued.Gateway == nil || issued.Gateway.Ticket == "" {
		t.Fatalf("gateway open = %+v", issued)
	}
	dsn, err := h.srv.pam.gatewaySessionCredential(ctx, h.tenant, issued.ID)
	if err != nil {
		t.Fatalf("reopen the session credential: %v", err)
	}
	parsed, err := url.Parse(string(dsn))
	if err != nil {
		t.Fatal(err)
	}
	login := parsed.User.Username()
	// The session's credential verifies as its administrator DSN does: a root
	// file the gateway's host does not have.
	if parsed.Query().Get("sslmode") != "verify-full" || parsed.Query().Get("sslrootcert") != pg.caFile {
		t.Fatalf("the session credential does not name the control plane's root file")
	}
	a201Await(t, "the gateway holds the session", func() bool {
		for _, id := range gw.Sessions() {
			if id == issued.ID {
				return true
			}
		}
		return false
	})
	// The gateway's host has no root file: the file stays on the control
	// plane's side while the gateway signs in.
	away := pg.caFile + ".control-plane-only"
	if err := os.Rename(pg.caFile, away); err != nil {
		t.Fatal(err)
	}
	restored := false
	restore := func() {
		if !restored {
			restored = true
			if err := os.Rename(away, pg.caFile); err != nil {
				t.Fatal(err)
			}
		}
	}
	defer restore()

	api := httptest.NewServer(h.srv.Handler())
	defer api.Close()
	ticketFile := filepath.Join(t.TempDir(), "session.ticket")
	if err := os.WriteFile(ticketFile, []byte(issued.Gateway.Ticket+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	local := probe.Addr().String()
	_ = probe.Close()
	var cliOut lockedBuffer
	cctx, ccancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		cli.Run(cctx, []string{"access", "sessions", "connect", issued.ID, "--ticket-file", ticketFile, "--listen", local},
			cli.Env{Server: api.URL, Token: requester, Tenant: h.tenant, HTTPClient: api.Client()}, strings.NewReader(""), &cliOut, &cliOut)
	}()
	defer func() { ccancel(); <-done }()
	for start := time.Now(); ; time.Sleep(100 * time.Millisecond) {
		if c, err := net.DialTimeout("tcp", local, 200*time.Millisecond); err == nil {
			_ = c.Close()
			break
		}
		select {
		case <-done:
			t.Fatalf("CLI connect exited: %s", cliOut.String())
		default:
		}
		if time.Since(start) > 20*time.Second {
			t.Fatalf("CLI tunnel not listening: %s", cliOut.String())
		}
	}
	connectCtx, connectCancel := context.WithTimeout(ctx, 20*time.Second)
	conn, err := pgconn.Connect(connectCtx, "postgres://client-without-credential@"+local+"/postgres?sslmode=disable&connect_timeout=15")
	connectCancel()
	if err != nil {
		t.Fatalf("stock client through the gateway to a private-CA database: %v (cli: %s; gateway: %s)", err, cliOut.String(), gatewayLog.String())
	}
	defer func() { _ = conn.Close(context.Background()) }()
	result := conn.ExecParams(ctx, "SELECT current_user, ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()", nil, nil, nil, nil).Read()
	if result.Err != nil || len(result.Rows) != 1 || string(result.Rows[0][0]) != login || string(result.Rows[0][1]) != "t" {
		t.Fatalf("through the gateway = %q err=%v, want %s over TLS", result.Rows, result.Err, login)
	}
	// The database accepts nothing but TLS: the gateway's upstream was
	// verified against the carried CA, not a plaintext fallback.
	plainCtx, plainCancel := context.WithTimeout(ctx, 10*time.Second)
	adminURL, _ := url.Parse(pg.adminDSN)
	if c, err := pgconn.Connect(plainCtx, "postgres://postgres:postgres@"+adminURL.Host+"/postgres?sslmode=disable&connect_timeout=5"); err == nil {
		_ = c.Close(ctx)
		plainCancel()
		t.Fatal("the private-CA database accepted a plaintext connection")
	}
	plainCancel()

	// The control plane revokes through its administrator DSN, whose root
	// file is on its own host.
	restore()
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+issued.ID+"/revoke", requester,
		"a256l1-revoke", map[string]any{"reason": "private CA proof"})
	if status != http.StatusAccepted {
		t.Fatalf("revoke = %d %s", status, body)
	}
	a201Await(t, "the gateway ends the revoked session", func() bool {
		for _, id := range gw.Sessions() {
			if id == issued.ID {
				return false
			}
		}
		return true
	})
	var check struct {
		Status string `json:"status"`
	}
	a201Await(t, "the session settles revoked", func() bool {
		_, b := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+issued.ID, requester, nil)
		return json.Unmarshal(b, &check) == nil && check.Status == "revoked"
	})
	t.Logf("A256L1_PRIVATE_CA_OK login=%s ssl=t", login)
}
