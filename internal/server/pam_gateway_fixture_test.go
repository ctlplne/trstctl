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
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/objectstore/s3test"
)

// gatewayFixture is a served control plane with a running access gateway, an
// sshd target that trusts the tenant SSH CA (bound to the gateway, host keys
// pinned), an embedded PostgreSQL target bound to the same gateway (and, when
// asked, a Redis target in a container), recording storage, and the tokens
// the proofs act with.
type gatewayFixture struct {
	t           *testing.T
	ctx         context.Context
	h           *roleHarness
	gw          *accessgateway.Gateway
	gatewayAddr string
	gatewayLog  *lockedBuffer
	sshd        pamSSHD
	objects     *s3test.Server
	// redisID, mysqlID and mongoID are the Redis, MySQL and MongoDB targets'
	// containers, which also carry the stock clients the proofs use;
	// clickhouse is the ClickHouse target (curl on this host is its client).
	redisID, mysqlID, mongoID string
	clickhouse                pamClickHouse
	auditKey                  *jose.SigningKey
	api                       *httptest.Server
	dir                       string
	// requester opens sessions; operator registers targets and terminates;
	// auditor reads and exports recordings.
	requester, reviewerOne, reviewerTwo, operator, auditor string
	// vaultDSN is the vaulted account's starting DSN (opts.vaulted).
	vaultDSN string
}

type gatewayFixtureOptions struct {
	// commandRules advertises the real current gateway executor and enables its versioned job kind.
	commandRules bool
	// duplicateWindow shortens only this fixture's broker deduplication window.
	duplicateWindow    time.Duration
	recordingRetention time.Duration
	// redis adds the Redis target "redis-gw" (A256), bound to the gateway.
	redis bool
	// mysqlNote adds the MySQL target "mysql-gw" (A256), bound to the
	// gateway, its app.notes table holding this note.
	mysqlNote string
	// mongoNote adds the MongoDB target "mongo-gw" (A256), bound to the
	// gateway, its orders.notes collection holding this note.
	mongoNote string
	// clickhouseNote adds the ClickHouse target "clickhouse-gw" (A256),
	// bound to the gateway, its lab.notes table holding this note.
	clickhouseNote string
	// kubernetes adds the Kubernetes target "k8s-gw" (A256), bound to the
	// gateway, served by this provider ("pam-k8s-provider", role operator).
	kubernetes DynamicSecretProviderRegistry
	// vaulted (A261) serves the secrets API and adds the provider
	// "pam-pg-vault", whose role db/orders rotates the PostgreSQL accounts
	// orders_app_a and orders_app_b as a static credential; vaultDSN is
	// orders_app_a's starting DSN.
	vaulted bool
	// agentBroker serves the AI agent broker, so a test can issue an agent
	// identity and revoke it in one call (A257).
	agentBroker bool
	// maxTTL raises the broker's session cap (a Kubernetes token lives at
	// least ten minutes); zero keeps three minutes.
	maxTTL time.Duration
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
	seedPAMPostgresTable(t, pgDSN, opts.commandRules)
	adminDSNRef := pamPostgresAdminFileRef(t, pgDSN)
	f := &gatewayFixture{t: t, objects: s3test.NewServer(t), gatewayLog: &lockedBuffer{}, dir: t.TempDir()}
	if opts.vaulted {
		_, f.vaultDSN = provisionTwoUserTarget(t, pgDSN)
	}
	var redisProviders, mysqlProviders, mongoProviders, clickhouseProviders DynamicSecretProviderRegistry
	if opts.redis {
		f.redisID, redisProviders = startPAMRedis(t)
	}
	if opts.mysqlNote != "" {
		f.mysqlID, mysqlProviders = startPAMMySQL(t, opts.mysqlNote)
	}
	if opts.mongoNote != "" {
		f.mongoID, mongoProviders = startPAMMongo(t, opts.mongoNote)
	}
	if opts.clickhouseNote != "" {
		f.clickhouse, clickhouseProviders = startPAMClickHouse(t, opts.clickhouseNote)
	}
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
	var eventOptions []events.OpenOption
	if opts.duplicateWindow > 0 {
		eventOptions = append(eventOptions, events.WithDuplicateWindowForTesting(opts.duplicateWindow))
	}
	kinds := []string{relay.KindAccessGatewaySession}
	if opts.commandRules {
		kinds = append(kinds, relay.KindAccessGatewayRulesSession)
	}
	f.h = newRoleHarnessWithEventOptions(t, []string{mtls.AgentRoleGateway}, kinds, eventOptions, func(d *Deps) {
		d.Protocols.SSH = config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}
		wirePAMPostgresProvider(d, adminDSNRef, time.Minute)
		if opts.vaulted {
			d.EnableSecretsAPI = true
			vault := config.DynamicSecretProviderConfig{TenantID: servedTestTenant, ID: "pam-pg-vault", Type: "postgresql",
				AdminDSNRef: adminDSNRef, Database: "postgres", Schema: "app", UsernamePrefix: "trstctl", AllowedRoles: []string{twoUserRole},
				MaxTTL: time.Hour.String(), AllowStaticRotation: true,
				RotationAccounts: map[string][]string{twoUserRole: {twoUserAccountA, twoUserAccountB}}}
			d.TenantDynamicSecretProviders[servedTestTenant] = append(d.TenantDynamicSecretProviders[servedTestTenant],
				newConfiguredDynamicProvider(vault, map[string]bool{twoUserRole: true}, time.Hour,
					integrationCredentialResolver{store: d.Store, kek: d.KEK, crypto: d.TenantCrypto}, nil))
		}
		var databaseTargets []PAMDatabaseTarget
		if opts.redis {
			d.TenantDynamicSecretProviders[servedTestTenant] = append(d.TenantDynamicSecretProviders[servedTestTenant], redisProviders.ForTenant(servedTestTenant)...)
			databaseTargets = append(databaseTargets, PAMDatabaseTarget{TargetType: "redis", TenantID: servedTestTenant, ID: "redis-gw", ProviderID: "pam-redis-provider",
				AllowedRoles: []string{"redis-writer"}, GatewayAgentID: gatewayID, GatewayAddress: f.gatewayAddr})
		}
		if opts.mysqlNote != "" {
			d.TenantDynamicSecretProviders[servedTestTenant] = append(d.TenantDynamicSecretProviders[servedTestTenant], mysqlProviders.ForTenant(servedTestTenant)...)
			databaseTargets = append(databaseTargets, PAMDatabaseTarget{TargetType: "mysql", TenantID: servedTestTenant, ID: "mysql-gw", ProviderID: "pam-mysql-provider",
				AllowedRoles: []string{"mysql-reader"}, GatewayAgentID: gatewayID, GatewayAddress: f.gatewayAddr})
		}
		if opts.mongoNote != "" {
			d.TenantDynamicSecretProviders[servedTestTenant] = append(d.TenantDynamicSecretProviders[servedTestTenant], mongoProviders.ForTenant(servedTestTenant)...)
			databaseTargets = append(databaseTargets, PAMDatabaseTarget{TargetType: "mongodb", TenantID: servedTestTenant, ID: "mongo-gw", ProviderID: "pam-mongo-provider",
				AllowedRoles: []string{"mongo-reader"}, GatewayAgentID: gatewayID, GatewayAddress: f.gatewayAddr})
		}
		if opts.kubernetes != nil {
			d.TenantDynamicSecretProviders[servedTestTenant] = append(d.TenantDynamicSecretProviders[servedTestTenant], opts.kubernetes.ForTenant(servedTestTenant)...)
			databaseTargets = append(databaseTargets, PAMDatabaseTarget{TargetType: "kubernetes", TenantID: servedTestTenant, ID: "k8s-gw", ProviderID: "pam-k8s-provider",
				AllowedRoles: []string{"operator"}, GatewayAgentID: gatewayID, GatewayAddress: f.gatewayAddr})
		}
		if opts.clickhouseNote != "" {
			d.TenantDynamicSecretProviders[servedTestTenant] = append(d.TenantDynamicSecretProviders[servedTestTenant], clickhouseProviders.ForTenant(servedTestTenant)...)
			databaseTargets = append(databaseTargets, PAMDatabaseTarget{TargetType: "clickhouse", TenantID: servedTestTenant, ID: "clickhouse-gw", ProviderID: "pam-clickhouse-provider",
				AllowedRoles: []string{"reader"}, GatewayAgentID: gatewayID, GatewayAddress: f.gatewayAddr})
		}
		maxTTL := 3 * time.Minute
		if opts.maxTTL > 0 {
			maxTTL = opts.maxTTL
		}
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: maxTTL, ExpiryInterval: 50 * time.Millisecond,
			RecordingRetention: opts.recordingRetention, Attestors: []attest.Attestor{servedPAMAttestor{}},
			PostgresTargets: []PAMPostgresTarget{{TenantID: servedTestTenant, ID: "pg-gw", ProviderID: "pam-pg-provider",
				AllowedRoles: []string{"readonly"}, GatewayAgentID: gatewayID, GatewayAddress: f.gatewayAddr}},
			DatabaseTargets: databaseTargets}
		d.ArchiveObjectStore = f.objects.Open(t)
		d.AuditSigningKey = f.auditKey
		if opts.agentBroker {
			d.AgentBroker = AgentBrokerConfig{Enabled: true, TrustDomain: "served.test", PolicyModule: servedBrokerAllowPolicy}
		}
	})
	h := f.h
	beat := &transport.HeartbeatRequest{AgentID: h.agent, Version: "a255", Status: "active"}
	if opts.commandRules {
		beat.Executors = &transport.ExecutorReport{Version: "a262", Kinds: []transport.ExecutorKind{{Kind: relay.KindAccessGatewaySession}, {Kind: relay.KindAccessGatewayRulesSession}}}
	}
	if _, err := h.client.Heartbeat(context.Background(), beat); err != nil {
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
