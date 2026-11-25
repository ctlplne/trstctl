// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/rotation"
	"trstctl.com/trstctl/internal/store"
)

func TestServedDatabaseGatewayRecoversStartAndRedemptionAfterProjectionFailure(t *testing.T) {
	pgDSN, stopPostgres := startPAMPostgres(t)
	t.Cleanup(stopPostgres)
	adminFile := pamPostgresAdminFileRef(t, pgDSN)
	gatewayListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gatewayListener.Close() })
	gatewayAddress := gatewayListener.Addr().String()
	const idempotencyKey = "database-gateway-recovery"
	gatewayID := agentRowID(servedTestTenant, "role-agent")
	var resultProtector orchestrator.ResultProtector
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleGateway}, []string{relay.KindAccessGatewaySession},
		withProtectedSecretsEnabled(t, nil), func(d *Deps) {
			resultProtector = d.IdempotencyResultProtector
			wirePAMPostgresProvider(d, adminFile, time.Minute)
			d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: time.Minute,
				Attestors: []attest.Attestor{servedPAMAttestor{}}, PostgresTargets: []PAMPostgresTarget{{TenantID: servedTestTenant,
					ID: "recover-postgres", ProviderID: "pam-pg-provider", AllowedRoles: []string{"readonly"},
					GatewayAgentID: gatewayID, GatewayAddress: gatewayAddress}}}
		})
	startServedExternalCADispatcher(t, h.servedHarness)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "review", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	pam := h.srv.pam
	target, err := pam.databaseTarget(ctx, h.tenant, pamTargetPostgres, "recover-postgres")
	if err != nil {
		t.Fatal(err)
	}
	const requester = "review-operator"
	token := seedScopedTokenSubject(t, h.store, h.tenant, requester, "access:write")
	reviewerOne := seedScopedTokenSubject(t, h.store, h.tenant, "recover-reviewer-one", "access:approve")
	reviewerTwo := seedScopedTokenSubject(t, h.store, h.tenant, "recover-reviewer-two", "access:approve")
	req := api.PAMSessionRequest{TargetType: pamTargetPostgres, TargetID: "recover-postgres", Role: "readonly",
		Reason: "review gateway projection recovery", Method: "stub_pam", TTLSeconds: 60, Payload: []byte("genuine")}
	body := map[string]any{"target_type": req.TargetType, "target_id": req.TargetID, "role": req.Role, "reason": req.Reason,
		"method": req.Method, "ttl_seconds": req.TTLSeconds, "payload_base64": base64.StdEncoding.EncodeToString(req.Payload)}
	servedPAMApproveOpen(t, h.servedHarness, token, reviewerOne, reviewerTwo, idempotencyKey, body)
	req.RequestID = body["request_id"].(string)
	req.ApprovalRequestID = body["approval_request_id"].(string)
	req.IntentDigest = body["intent_digest"].(string)
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl-pam-session\x00"+h.tenant+"\x00"+idempotencyKey)).String()
	jobKey := accessgateway.JobKey(id)
	const collisionKind = "review.database-gateway-collision"
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := h.srv.outbox.Enqueue(ctx, tx, orchestrator.Entry{TenantID: h.tenant, Destination: collisionKind,
			IdempotencyKey: jobKey, Payload: []byte("{}")})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	_, err = pam.OpenPAMSession(ctx, h.tenant, idempotencyKey, requester, req)
	if !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("the interrupted projection returned %v", err)
	}
	if _, err := h.store.GetPAMSession(ctx, h.tenant, id); !store.IsNotFound(err) {
		t.Fatalf("a failed outbox insert left a projected session: %v", err)
	}
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions", token, idempotencyKey, body); status == http.StatusCreated {
		t.Fatal("the HTTP open returned a ticket before SQL could project the start and job")
	}
	event, found, err := pam.log.EventByID(ctx, databaseGatewayStartedEventID(h.tenant, id))
	if err != nil || !found {
		t.Fatalf("recover retained database start: %t, %v", found, err)
	}
	var started projections.PAMDatabaseGatewayStarted
	if err := json.Unmarshal(event.Data, &started); err != nil || started.BackendRef == "" || started.Attestation == nil {
		t.Fatal("retained gateway start has no lease reference")
	}
	// The same request can return its already-issued lease before the row is
	// projected. Fail gateway selection on that retry without closing the lease.
	missingGateway := *target
	missingGateway.cfg.GatewayAgentID = uuid.NewString()
	if _, err := pam.openDatabaseProvider(ctx, h.tenant, idempotencyKey, requester, id, started.StartedAt,
		started.ExpiresAt, *started.Attestation, req, &missingGateway); err == nil {
		t.Fatal("retry selected a gateway that was never enrolled")
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM outbox WHERE tenant_id = $1 AND destination = $2 AND idempotency_key = $3`,
			h.tenant, collisionKind, jobKey)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// CR-276: the authorized requester can finish the exact retained start
	// before the projector catches up, and can repeat the original result.
	for _, actor := range []string{"different-requester", requester} {
		changed := req
		if actor == requester {
			changed.Reason = "different reviewed command"
		}
		if session, err := pam.OpenPAMSession(ctx, h.tenant, idempotencyKey, actor, changed); err == nil || session.Gateway != nil {
			t.Fatal("a different activation recovered the gateway ticket")
		}
	}
	changedRun := req
	changedRun.RunID = "different-bundle-run"
	if session, err := pam.OpenPAMSession(ctx, h.tenant, idempotencyKey, requester, changedRun); err == nil || session.Gateway != nil {
		t.Fatal("a different bundle run recovered the gateway ticket")
	}
	recovered := servedPAMOpen(t, h.servedHarness, token, idempotencyKey, body)
	if recovered.Gateway == nil || recovered.Gateway.Ticket == "" || recovered.ID != id ||
		accessgateway.TicketDigest(recovered.Gateway.Ticket) != started.GatewayTicketDigest {
		t.Fatal("the exact HTTP request did not recover the original ticket")
	}
	if err := pam.projector.Apply(ctx, event); err != nil {
		t.Fatalf("catch up the retained start: %v", err)
	}
	if err := pam.projector.Apply(ctx, event); err != nil {
		t.Fatalf("exact start replay: %v", err)
	}
	replay, err := pam.OpenPAMSession(ctx, h.tenant, idempotencyKey, requester, req)
	if err != nil || replay.Gateway == nil || crypto.SHA256Hex(replay.Gateway.Ticket) != started.GatewayTicketDigest ||
		replay.Gateway.Address != recovered.Gateway.Address {
		t.Fatalf("the exact request did not replay the recovered result: %v", err)
	}
	secret.Wipe(replay.Gateway.Ticket)
	// The served HTTP result cache retains only the reference, and both the
	// first response and its cache hit derive the original ticket on demand.
	for range 2 {
		response := servedPAMOpen(t, h.servedHarness, token, idempotencyKey, body)
		if response.ID != id || response.Gateway == nil || accessgateway.TicketDigest(response.Gateway.Ticket) != started.GatewayTicketDigest {
			t.Fatal("the served replay did not present the original gateway ticket")
		}
	}
	var binding, codec string
	var sealedResult []byte
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT request_binding, result_codec, result FROM idempotency_keys
			WHERE tenant_id = $1 AND key = $2`, h.tenant, idempotencyKey).Scan(&binding, &codec, &sealedResult)
	}); err != nil {
		t.Fatal(err)
	}
	recording, err := resultProtector.Open(ctx, h.tenant, idempotencyKey, binding, codec, sealedResult)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(recording)
	ticketBytes := []byte(recovered.Gateway.Ticket)
	defer secret.Wipe(ticketBytes)
	if !bytes.Contains(recording, []byte("database_gateway_session_id")) ||
		bytes.Contains(recording, ticketBytes) || bytes.Contains(event.Data, ticketBytes) {
		t.Fatal("the event and response cache must retain only ticket-free recovery data")
	}
	// The retained job must still be the exact one named by the event,
	// even if the key, active status and required agent ID match.
	jobIntent := started.Intent()
	originalJob, err := json.Marshal(jobIntent)
	if err != nil {
		t.Fatal(err)
	}
	jobIntent.Record = !jobIntent.Record
	differentJob, err := json.Marshal(jobIntent)
	if err != nil {
		t.Fatal(err)
	}
	setJobPayload := func(value []byte) {
		t.Helper()
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE outbox SET payload = $4
				WHERE tenant_id = $1 AND destination = $2 AND idempotency_key = $3`,
				h.tenant, relay.KindAccessGatewaySession, jobKey, value)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	setJobPayload(differentJob)
	if session, err := pam.OpenPAMSession(ctx, h.tenant, idempotencyKey, requester, req); err == nil || session.Gateway != nil {
		t.Fatal("a noncanonical gateway job released the ticket")
	}
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions", token, idempotencyKey, body); status == http.StatusCreated {
		t.Fatal("the cached HTTP result released a ticket for a noncanonical gateway job")
	}
	setJobPayload(originalJob)
	jobs, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindAccessGatewaySession}, Limit: 10, LeaseSeconds: 30})
	if err != nil || len(jobs.Jobs) != 1 {
		t.Fatalf("recovery must expose one gateway claim: %v", err)
	}
	job := jobs.Jobs[0]
	redemption := &transport.RedeemJobCredentialRequest{JobID: job.JobID, Attempt: job.Attempt}
	if _, err := h.client.RedeemJobCredential(ctx, redemption); err == nil {
		t.Fatal("an old agent redeemed the guarded gateway job")
	}
	value := useRecoveredDatabaseGatewayTicket(t, ctx, gatewayListener, h, recovered, relay.Job{JobID: job.JobID, Kind: job.Kind,
		Attempt: job.Attempt, Payload: job.Payload, LeaseExpiresUnix: job.LeaseExpiresUnix})
	defer secret.Wipe(value)
	adminURL, err := url.Parse(pgDSN)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(adminURL.Query().Get("sslrootcert")) // #nosec G304 -- CA path from this test's disposable PostgreSQL fixture (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	verificationTrust := &dynsecret.DatabaseTransport{CAPEM: caPEM, ServerName: "localhost",
		Dialer: netsec.NewDatabaseDialer(netsec.DatabaseDialOptions{OperatorFile: true})}
	conn, err := dynsecret.OpenPostgresCredential(ctx, value, verificationTrust)
	if err != nil {
		t.Fatalf("native lease must still sign in after recovery: %v", err)
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatal(err)
	}
	const missingColumn = "review_fixture_missing_field"
	if err := rotation.VerifyPostgresCredentialWithTransport(ctx, value, "SELECT "+missingColumn, verificationTrust); err == nil ||
		strings.Contains(err.Error(), missingColumn) {
		t.Fatal("live verification exposed the server's query diagnostic")
	}
	legacy := started.Intent()
	legacy.DatabaseRoute = nil
	legacyPayload, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	var legacyJobID int64
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		var err error
		legacyJobID, err = h.srv.outbox.Enqueue(ctx, tx, orchestrator.Entry{TenantID: h.tenant, Destination: relay.KindAccessGatewaySession,
			IdempotencyKey: "retained-gateway-job", Payload: legacyPayload, RequiredAgentRole: mtls.AgentRoleGateway, RequiredAgentID: gatewayID})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	jobs, err = h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindAccessGatewaySession}, Limit: 10, LeaseSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	legacyClaimed := false
	for _, claimed := range jobs.Jobs {
		if claimed.JobID == legacyJobID {
			legacyClaimed = true
			if _, err := h.client.RedeemJobCredential(transport.WithGuardedDatabaseRedemption(ctx),
				&transport.RedeemJobCredentialRequest{JobID: claimed.JobID, Attempt: claimed.Attempt}); err == nil {
				t.Fatal("retained job without a route redeemed credentials")
			}
		}
	}
	if !legacyClaimed {
		t.Fatal("the retained job did not reach the redemption boundary")
	}
	if err := h.store.RecallPAMGatewayJob(ctx, h.tenant, id, relay.KindAccessGatewaySession, jobKey, time.Now()); err != nil {
		t.Fatal(err)
	}
	if row, err := h.store.GetPAMSession(ctx, h.tenant, id); err != nil || row.Status != api.PAMSessionStatusActive {
		t.Fatal("the recall check must run before the PAM status changes")
	}
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions", token, idempotencyKey, body); status == http.StatusCreated {
		t.Fatal("the cached HTTP activation released its ticket after gateway recall")
	}
	ended := projections.PAMSessionGatewayEnded{ID: id, Ended: "recalled", Connections: 0, Attempt: job.Attempt, EndedAt: time.Now().UTC()}
	if err := pam.appendProject(ctx, h.tenant, projections.EventPAMSessionGatewayEnded, ended); err != nil {
		t.Fatal(err)
	}
	if session, err := pam.OpenPAMSession(ctx, h.tenant, idempotencyKey, requester, req); err == nil || session.Gateway != nil {
		t.Fatal("a finished gateway session returned its ticket")
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM outbox WHERE tenant_id = $1 AND destination = $2 AND idempotency_key = $3`,
			h.tenant, relay.KindAccessGatewaySession, jobKey)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := pam.projector.Apply(ctx, event); err != nil {
		t.Fatal(err)
	}
	row, err := h.store.GetPAMSession(ctx, h.tenant, id)
	if err != nil || row.GatewayEndedAt == nil {
		t.Fatal("late start replay reopened the finished gateway session")
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE tenant_id = $1 AND idempotency_key = $2`, h.tenant, jobKey).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Error("late start replay recreated a finished gateway job")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type recoveredDatabaseGatewayClaim struct {
	*sshCollectionServedChannel
	job      *relay.Job
	redeemed chan []byte
}

func (c *recoveredDatabaseGatewayClaim) ClaimJobs(_ context.Context, _ []string, _, _ int) ([]relay.Job, error) {
	if c.job == nil {
		return nil, nil
	}
	job := *c.job
	c.job = nil
	return []relay.Job{job}, nil
}

func (c *recoveredDatabaseGatewayClaim) RedeemJobCredential(ctx context.Context, id int64, attempt int) (map[string][]byte, error) {
	material, err := c.sshCollectionServedChannel.RedeemJobCredential(ctx, id, attempt)
	if err == nil && len(material) == 1 {
		for _, value := range material {
			c.redeemed <- append([]byte(nil), value...)
		}
	}
	return material, err
}

// Serve the exact job already claimed over gRPC. Everything after claim
// selection, including redemption and verified requester traffic, is live.
func useRecoveredDatabaseGatewayTicket(t *testing.T, ctx context.Context, raw net.Listener, h *roleHarness,
	opened servedPAMSessionResponse, job relay.Job) []byte {
	t.Helper()
	cert, err := mtls.NewRenewingServerCertificate(h.srv.AgentCACertPEM(), []string{"127.0.0.1"}, func(csr []byte) ([]byte, error) {
		result, err := h.client.SignGatewayServerCertificate(ctx, &transport.SignGatewayServerCertificateRequest{
			CSRDER: csr, Hosts: []string{"127.0.0.1"},
		})
		if err != nil {
			return nil, err
		}
		serverCertificate, _ := pem.Decode(result.CertificatePEM)
		if serverCertificate == nil {
			return nil, errors.New("the enrolled gateway did not receive a certificate")
		}
		return serverCertificate.Bytes, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cert.Close)
	secured, err := mtls.GatewayWrapListener(raw, cert)
	if err != nil {
		t.Fatal(err)
	}
	channel := &recoveredDatabaseGatewayClaim{sshCollectionServedChannel: &sshCollectionServedChannel{t: t, h: h},
		job: &job, redeemed: make(chan []byte, 1)}
	gateway, err := accessgateway.New(accessgateway.Config{Channel: channel, Listener: secured, ClaimInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = gateway.Run(runCtx)
	}()
	t.Cleanup(func() {
		stop()
		<-done
		select {
		case value := <-channel.redeemed:
			secret.Wipe(value)
		default:
		}
	})
	ticket, err := secret.NewFrom([]byte(opened.Gateway.Ticket))
	if err != nil {
		t.Fatal(err)
	}
	defer ticket.Destroy()
	var wire net.Conn
	a201Await(t, "the original gateway admits the recovered ticket", func() bool {
		conn, err := mtls.GatewayDial(ctx, opened.Gateway.Address, []byte(opened.Gateway.CAPEM), opened.Gateway.SPIFFEID)
		if err != nil {
			return false
		}
		if _, err := admitAtGateway(conn, opened.ID, ticket); err != nil {
			_ = conn.Close()
			return false
		}
		wire = conn
		return true
	})
	defer func() { _ = wire.Close() }()
	config, err := pgx.ParseConfig("host=127.0.0.1 port=5432 user=review password=plain dbname=postgres sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	config.DialFunc = func(context.Context, string, string) (net.Conn, error) { return wire, nil }
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("the requester could not sign in through the recovered gateway")
	}
	defer func() { _ = conn.Close(ctx) }()
	var one int
	if err := conn.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
		t.Fatal("the recovered gateway session did not run its native query")
	}
	select {
	case value := <-channel.redeemed:
		return value
	case <-ctx.Done():
		t.Fatal("the current gateway did not redeem exactly one credential")
		return nil
	}
}

func TestServedVaultedGatewayRechecksTheCurrentCredentialAgainstTheJob(t *testing.T) {
	const account = "review/database-account"
	const targetID = "vaulted-review"
	const databaseAddress = "127.0.0.1:5432"
	const gatewayAddress = "127.0.0.1:4444"
	admin := writeServedCredentialFile(t, "database-admin", "postgres://review:plain@"+databaseAddress+"/orders?sslmode=verify-full")
	gatewayID := agentRowID(servedTestTenant, "role-agent")
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleGateway}, []string{relay.KindAccessGatewaySession}, withSecretsEnabled(t, nil), func(d *Deps) {
		provider := config.DynamicSecretProviderConfig{ID: "vaulted-postgres", Type: "postgresql", TenantID: servedTestTenant,
			AdminDSNRef: admin, Database: "orders", AllowedRoles: []string{account}, AllowStaticRotation: true,
			RotationAccounts: map[string][]string{account: {"account_a", "account_b"}}}
		configured := newConfiguredDynamicProvider(provider, map[string]bool{account: true}, time.Minute,
			integrationCredentialResolver{store: d.Store, kek: d.KEK, crypto: d.TenantCrypto}, nil)
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {configured}}
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: time.Minute,
			Attestors: []attest.Attestor{servedPAMAttestor{}}, DatabaseTargets: []PAMDatabaseTarget{{TargetType: pamTargetPostgres,
				ID: targetID, TenantID: servedTestTenant, ProviderID: provider.ID, AllowedRoles: []string{account},
				AccountSecret: account, GatewayAgentID: gatewayID, GatewayAddress: gatewayAddress}}}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "review", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	writer := seedScopedToken(t, h.store, h.tenant, "secrets:read", "secrets:write")
	initial := "postgres://account_a:plain@" + databaseAddress + "/orders?sslmode=verify-full"
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/store", writer, "seed-vaulted-route",
		map[string]any{"name": account, "value": initial}); status != http.StatusCreated {
		t.Fatalf("seed vaulted account: %d", status)
	}
	pam := h.srv.pam
	target, err := pam.databaseTarget(ctx, h.tenant, pamTargetPostgres, targetID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	attestation := attest.Attestation{ID: uuid.NewString(), Method: "stub_pam", Subject: "review-workload", VerifiedAt: now}
	req := api.PAMSessionRequest{TargetType: pamTargetPostgres, TargetID: targetID, Role: account, Reason: "vaulted route verification"}
	opened, err := pam.openDatabaseProvider(ctx, h.tenant, "open-vaulted-route", "review-operator", uuid.NewString(), now,
		now.Add(time.Minute), attestation, req, target)
	if err != nil || opened.Gateway == nil {
		t.Fatalf("start vaulted gateway session: %v", err)
	}
	jobs, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindAccessGatewaySession}, Limit: 10, LeaseSeconds: 30})
	if err != nil || len(jobs.Jobs) != 1 {
		t.Fatalf("claim vaulted job: %v", err)
	}
	job := jobs.Jobs[0]
	redemption := &transport.RedeemJobCredentialRequest{JobID: job.JobID, Attempt: job.Attempt}
	put := func(key, value string) {
		t.Helper()
		if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPut, "/api/v1/secrets/store/"+account, writer, key,
			map[string]any{"value": value}); status != http.StatusOK {
			t.Fatalf("replace vaulted fixture: %d", status)
		}
	}
	put("change-vaulted-db", "postgres://account_a:plain@"+databaseAddress+"/different?sslmode=verify-full")
	if _, err := h.client.RedeemJobCredential(transport.WithGuardedDatabaseRedemption(ctx), redemption); err == nil {
		t.Fatal("the held job returned a credential for a different initial database")
	}
	put("rotate-vaulted-login", "postgres://account_b:rotated@"+databaseAddress+"/orders?sslmode=verify-full")
	material, err := h.client.RedeemJobCredential(transport.WithGuardedDatabaseRedemption(ctx), redemption)
	if err != nil || len(material.Items) != 1 {
		t.Fatalf("the same-route rotation could not redeem the original attempt: %v", err)
	}
	credential := material.Items[0].Value
	defer secret.Wipe(credential)
	if user, ok := dynsecret.CredentialAccount("postgresql", credential); !ok || user != "account_b" {
		t.Fatal("the held job did not read the current same-route account")
	}
}
