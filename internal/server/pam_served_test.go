// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	embeddedpostgres "trstctl.com/trstctl/third_party/embedded-postgres"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// TestServedPAMJITBrokersPostgresAndSSHWithAuditAndExpiry is the PAM-01
// acceptance proof. It drives the assembled HTTP API: a requester presents an
// attested proof, trstctl brokers short-lived access to a real PostgreSQL target and
// a disposable sshd container that trusts the served SSH CA, emits audit/session
// events, and automatically expires the brokered access.
func TestServedPAMJITBrokersPostgresAndSSHWithAuditAndExpiry(t *testing.T) {
	const sshTTLSeconds int64 = 60
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	seedPAMPostgresTable(t, pgDSN)
	adminDSNRef := pamPostgresAdminFileRef(t, pgDSN)

	h := newOperatingServedHarness(t,
		config.Protocols{SSH: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		func(d *Deps) {
			wirePAMPostgresProvider(d, adminDSNRef, 5*time.Second)
			d.PAM = PAMConfig{
				Enabled:        true,
				DefaultTTL:     2 * time.Second,
				MaxTTL:         90 * time.Second,
				ExpiryInterval: 10 * time.Millisecond,
				Attestors:      []attest.Attestor{servedPAMAttestor{}},
				PostgresTargets: []PAMPostgresTarget{{
					TenantID: servedTestTenant, ID: "pg-main", ProviderID: "pam-pg-provider",
					AllowedRoles: []string{"readonly"},
				}},
				SSHTargets: []PAMSSHTarget{{
					TenantID:   servedTestTenant,
					ID:         "ssh-edge",
					Host:       "127.0.0.1",
					Port:       22,
					Principals: []string{"alice"},
				}},
			}
		},
	)
	startServedExternalCADispatcher(t, h)
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "pam-requester", "access:read", "access:write")
	reviewerOne := seedScopedTokenSubject(t, h.store, h.tenant, "pam-reviewer-one", "access:approve")
	reviewerTwo := seedScopedTokenSubject(t, h.store, h.tenant, "pam-reviewer-two", "access:approve")
	for _, tc := range []struct{ targetType, targetID, role string }{
		{"postgres", "pg-main", "writer"},
		{"ssh", "ssh-edge", "admin"},
	} {
		req := api.PAMSessionRequest{
			TargetType: tc.targetType, TargetID: tc.targetID, Role: tc.role,
			Method: "stub_pam", Payload: []byte("genuine"), SSHPublicKey: []byte("test-public-key"),
		}
		if err := h.srv.pam.validate(context.Background(), h.tenant, "unlisted-role-check", "pam-requester", req); err == nil {
			t.Fatalf("PAM %s target accepted unlisted role %q", tc.targetType, tc.role)
		}
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/sessions", admin,
			"unlisted-role-"+tc.targetType, map[string]any{
				"target_type": tc.targetType, "target_id": tc.targetID, "role": tc.role,
				"method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")),
				"ssh_public_key": "test-public-key",
			})
		if status != http.StatusUnprocessableEntity {
			t.Fatalf("PAM %s unlisted role status=%d, want 422; body=%s", tc.targetType, status, body)
		}
	}
	otherTenant := "22222222-2222-2222-2222-222222222222"
	for _, targetType := range []string{"postgres", "ssh"} {
		req := api.PAMSessionRequest{
			TargetType: targetType, TargetID: map[string]string{"postgres": "pg-main", "ssh": "ssh-edge"}[targetType],
			Role: "readonly", Method: "stub_pam", Payload: []byte("genuine"), SSHPublicKey: []byte("test-public-key"),
		}
		if err := h.srv.pam.validate(context.Background(), otherTenant, "foreign-tenant-check", "foreign-requester", req); err == nil {
			t.Fatalf("foreign tenant accepted PAM %s target %q", targetType, req.TargetID)
		}
	}
	if err := h.store.UpsertTenant(context.Background(), store.Tenant{TenantID: otherTenant, Name: "PAM foreign tenant"}); err != nil {
		t.Fatalf("register foreign tenant: %v", err)
	}
	foreign := seedScopedTokenSubject(t, h.store, otherTenant, "foreign-requester", "access:write")
	for _, targetType := range []string{"postgres", "ssh"} {
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/sessions", foreign,
			"foreign-tenant-"+targetType, map[string]any{
				"target_type": targetType, "target_id": map[string]string{"postgres": "pg-main", "ssh": "ssh-edge"}[targetType],
				"role": "readonly", "method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")),
				"ssh_public_key": "test-public-key",
			})
		if status != http.StatusUnprocessableEntity {
			t.Fatalf("foreign tenant PAM %s target status = %d, want 422; body=%s", targetType, status, body)
		}
	}
	for _, seconds := range []int64{-1, 91, 1 << 62} {
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/sessions", admin,
			fmt.Sprintf("pam-invalid-ttl-%d", seconds), map[string]any{
				"target_type": "postgres", "target_id": "pg-main", "role": "readonly",
				"method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")),
				"ttl_seconds": seconds,
			})
		if status != http.StatusUnprocessableEntity {
			t.Fatalf("PAM TTL %d status = %d, want 422 before mint; body=%s", seconds, status, body)
		}
	}

	pg := servedPAMReviewedOpen(t, h, admin, reviewerOne, reviewerTwo, "pam-01-postgres", map[string]any{
		"target_type":    "postgres",
		"target_id":      "pg-main",
		"role":           "readonly",
		"reason":         "production incident 42",
		"method":         "stub_pam",
		"payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")),
		"ttl_seconds":    2,
	})
	if pg.ID == "" || pg.TargetType != "postgres" || pg.Status != "active" || pg.Postgres == nil || pg.Postgres.DSN == "" {
		t.Fatalf("postgres PAM response = %+v", pg)
	}
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/access/sessions/"+pg.ID, admin, nil)
	if status != http.StatusOK {
		t.Fatalf("postgres PAM readback status=%d; body=%s", status, body)
	}
	var readback servedPAMSessionResponse
	if err := json.Unmarshal(body, &readback); err != nil {
		t.Fatalf("decode postgres PAM readback: %v", err)
	}
	if readback.Attestation == nil || readback.Attestation.ID != pg.Attestation.ID ||
		readback.Attestation.Method != "stub_pam" || readback.Attestation.Subject != "pam-workload" ||
		readback.Attestation.VerifiedAt.IsZero() || len(readback.Attestation.Selectors) != 1 ||
		readback.Attestation.Selectors[0] != "pam:test" {
		t.Fatalf("postgres PAM readback lost verified attestation evidence: %+v", readback.Attestation)
	}
	if readback.Postgres != nil || readback.SSH != nil {
		t.Fatal("PAM metadata readback returned one-time credential material")
	}
	if !strings.HasPrefix(pg.Postgres.Username, "trstctl_pam_") {
		t.Fatalf("postgres PAM username = %q", pg.Postgres.Username)
	}
	assertPAMPostgresAccess(t, pg.Postgres.DSN, true)
	if nativeExpiry := pamPostgresRoleValidUntil(t, pgDSN, pg.Postgres.Username); nativeExpiry.After(pg.ExpiresAt.Add(time.Second)) {
		t.Fatalf("PostgreSQL role natively valid until %s, after PAM session deadline %s", nativeExpiry, pg.ExpiresAt)
	}
	// Leave the PAM cleanup worker stopped until after the native deadline.
	// PostgreSQL itself must reject a new login even while the role still exists.
	for time.Now().Before(pg.ExpiresAt.Add(250 * time.Millisecond)) {
		time.Sleep(25 * time.Millisecond)
	}
	if !pamPostgresRoleExists(t, pgDSN, pg.Postgres.Username) {
		t.Fatal("PostgreSQL role disappeared before the PAM cleanup worker ran")
	}
	assertPAMPostgresAccess(t, pg.Postgres.DSN, false)

	worker, ok := any(h.srv).(interface{ RunPAMSessionExpiry(context.Context) })
	if !ok {
		t.Fatal("served PAM expiry worker is not wired")
	}
	workerCtx, cancelWorker := context.WithCancel(context.Background())
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		worker.RunPAMSessionExpiry(workerCtx)
	}()
	t.Cleanup(func() {
		cancelWorker()
		<-workerDone
	})

	caPub, err := h.srv.protocols.ssh.AuthorityKey()
	if err != nil {
		t.Fatalf("ssh authority key: %v", err)
	}
	sshd := startPAMSSHD(t, caPub)
	keyPath, publicKey := generatePAMSSHKey(t)
	sshRequest := map[string]any{
		"target_type":    "ssh",
		"target_id":      "ssh-edge",
		"role":           "user",
		"reason":         "production incident 42",
		"method":         "stub_pam",
		"payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")),
		"ssh_public_key": publicKey,
		"ssh_principal":  "alice",
		"ttl_seconds":    sshTTLSeconds,
	}
	ssh := servedPAMReviewedOpen(t, h, admin, reviewerOne, reviewerTwo, "pam-01-ssh", sshRequest)
	if ssh.ID == "" || ssh.TargetType != "ssh" || ssh.Status != "active" || ssh.SSH == nil || ssh.SSH.Certificate == "" {
		t.Fatalf("ssh PAM response = %+v", ssh)
	}
	if ssh.SSH.Principal != "alice" || ssh.SSH.KeyID == "" || ssh.SSH.Serial == 0 {
		t.Fatalf("ssh PAM certificate metadata = %+v", ssh.SSH)
	}
	// Exercise the positive path before replay and database assertions consume
	// the lease. Native sshd startup and a first handshake can be slow under
	// race/coverage on a loaded host; expiry is asserted below at ValidBefore.
	assertPAMSSHAccess(t, sshd, keyPath, ssh.SSH.Certificate, true)
	issuedBeforeReplay := pamEventCount(t, h, "ssh.cert.issued")
	cacheReplay := servedPAMOpen(t, h, admin, "pam-01-ssh", sshRequest)
	if cacheReplay.ID != ssh.ID || cacheReplay.SSH == nil || cacheReplay.SSH.Certificate != ssh.SSH.Certificate {
		t.Fatal("an exact SSH PAM HTTP replay did not return the original one-time certificate")
	}
	if after := pamEventCount(t, h, "ssh.cert.issued"); after != issuedBeforeReplay {
		t.Fatalf("SSH PAM HTTP replay signed %d additional certificates", after-issuedBeforeReplay)
	}
	// Simulate normal idempotency-result retention without changing the
	// event-projected PAM session. The old key must remain spent at the API.
	if _, err := h.store.SystemPool().Exec(context.Background(),
		`DELETE FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`, h.tenant, "pam-01-ssh"); err != nil {
		t.Fatalf("expire protected HTTP replay cache: %v", err)
	}
	if status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/sessions", admin,
		"pam-01-ssh", sshRequest); status != http.StatusConflict {
		t.Fatalf("retired SSH PAM idempotency key status = %d, want 409", status)
	}
	if after := pamEventCount(t, h, "ssh.cert.issued"); after != issuedBeforeReplay {
		t.Fatalf("retired SSH PAM idempotency key signed %d additional certificates", after-issuedBeforeReplay)
	}
	if _, err := h.srv.pam.OpenPAMSession(context.Background(), h.tenant, "pam-01-ssh", "pam-requester", api.PAMSessionRequest{
		RequestID:         sshRequest["request_id"].(string),
		ApprovalRequestID: sshRequest["approval_request_id"].(string),
		IntentDigest:      sshRequest["intent_digest"].(string),
		TargetType:        "ssh", TargetID: "ssh-edge", Role: "user", Reason: "production incident 42",
		Method: "stub_pam", Payload: []byte("genuine"), SSHPublicKey: []byte(publicKey),
		SSHPrincipal: "alice", TTLSeconds: sshTTLSeconds,
	}); err == nil {
		t.Fatal("replaying an SSH PAM idempotency key after the HTTP cache was bypassed minted a second certificate")
	}
	if after := pamEventCount(t, h, "ssh.cert.issued"); after != issuedBeforeReplay {
		t.Fatalf("SSH PAM replay signed %d additional certificates", after-issuedBeforeReplay)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !pamPostgresRoleExists(t, pgDSN, pg.Postgres.Username) && h.hasEvent(t, "pam.session.expired") {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if pamPostgresRoleExists(t, pgDSN, pg.Postgres.Username) {
		t.Fatalf("postgres PAM role %q did not auto-expire", pg.Postgres.Username)
	}
	assertPAMPostgresAccess(t, pg.Postgres.DSN, false)
	for time.Now().Before(ssh.SSH.ValidBefore.Add(250 * time.Millisecond)) {
		time.Sleep(25 * time.Millisecond)
	}
	assertPAMSSHAccess(t, sshd, keyPath, ssh.SSH.Certificate, false)

	for _, eventType := range []string{"attestation.verified", "attestation.bound", "pam.session.started", "pam.session.expired", "ssh.cert.issued"} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("served PAM did not emit %s", eventType)
		}
	}
	if h.logContains(t, pg.Postgres.DSN) || h.logContains(t, ssh.SSH.Certificate) {
		t.Fatal("PAM credential material reached the event log")
	}
}

func TestPAMSSHRequiresAnExplicitPrincipalAllowlist(t *testing.T) {
	if principalAllowed(nil, "alice") {
		t.Fatal("empty principal list granted SSH access to alice")
	}
	if principalAllowed([]string{"alice"}, "bob") {
		t.Fatal("SSH target granted an unlisted principal")
	}
	if !principalAllowed([]string{"alice"}, "alice") {
		t.Fatal("SSH target refused its explicitly allowed principal")
	}
}

func TestPAMLegacySessionDoesNotInventAttestationEvidence(t *testing.T) {
	rec := store.PAMSession{ID: uuid.NewString(), Subject: "legacy-workload", AttestationID: "att:legacy"}
	got := pamSessionFromStore(rec)
	if got.Attestation != nil {
		t.Fatalf("legacy session invented verified facts: %+v", got.Attestation)
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"attestation"`) {
		t.Fatalf("legacy session serialized an attestation it cannot prove: %s", data)
	}
}

func TestServedPAMUsesTenantManagedAttesterTrust(t *testing.T) {
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	seedPAMPostgresTable(t, pgDSN)
	adminDSNRef := pamPostgresAdminFileRef(t, pgDSN)
	fixture := servedDynamicK8sTrustFixture(t, "pam-tenant-trust")
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		wirePAMPostgresProvider(d, adminDSNRef, time.Minute)
		d.PAM = PAMConfig{Enabled: true, MaxTTL: time.Minute, PostgresTargets: []PAMPostgresTarget{{
			TenantID: servedTestTenant, ID: "tenant-pg", ProviderID: "pam-pg-provider", AllowedRoles: []string{"readonly"},
		}}}
	})
	startServedExternalCADispatcher(t, h)
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "pam-workload-requester", "access:write")
	reviewerOne := seedScopedTokenSubject(t, h.store, h.tenant, "pam-workload-reviewer-one", "access:approve")
	reviewerTwo := seedScopedTokenSubject(t, h.store, h.tenant, "pam-workload-reviewer-two", "access:approve")
	owner := seedScopedTokenSubject(t, h.store, h.tenant, "pam-trust-owner", "certs:issue", "issuers:write")
	request := map[string]any{
		"target_type": "postgres", "target_id": "tenant-pg", "role": "readonly", "method": "k8s_sat",
		"payload_base64": base64.StdEncoding.EncodeToString([]byte(fixture.SAT)), "ttl_seconds": 30,
		"request_id": uuid.NewString(),
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/session-requests", requester, "pam-before-trust", request)
	if status != http.StatusForbidden {
		t.Fatalf("PAM accepted a proof before tenant trust: status=%d body=%s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources", owner,
		"pam-tenant-trust-create", map[string]any{
			"name": "pam-k8s", "method": "k8s_sat", "issuer": "https://kubernetes.default.svc",
			"audience": "trstctl", "jwks": fixture.JWKS,
		})
	if status != http.StatusCreated {
		t.Fatalf("register PAM attester trust: status=%d body=%s", status, body)
	}
	var source servedWorkloadTrustSourceResponse
	if err := json.Unmarshal(body, &source); err != nil || source.ID == "" {
		t.Fatalf("decode PAM attester trust source: %v", err)
	}
	issued := servedPAMReviewedOpen(t, h, requester, reviewerOne, reviewerTwo, "pam-after-trust", request)
	if issued.Postgres == nil {
		t.Fatal("tenant-trusted PAM did not return a PostgreSQL credential")
	}
	assertPAMPostgresAccess(t, issued.Postgres.DSN, true)
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources/"+source.ID+"/revoke",
		owner, "pam-tenant-trust-revoke", map[string]any{"reason": "retire compromised signer"})
	if status != http.StatusOK {
		t.Fatalf("revoke PAM attester trust: status=%d body=%s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/access/sessions", requester, "pam-after-revoke", request)
	if status != http.StatusForbidden {
		t.Fatalf("PAM accepted proof after tenant trust revoke: status=%d body=%s", status, body)
	}
}

func TestServedPAMPostgresUsesProtectedProviderOutbox(t *testing.T) {
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	seedPAMPostgresTable(t, pgDSN)
	adminDSNRef := pamPostgresAdminFileRef(t, pgDSN)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		wirePAMPostgresProvider(d, adminDSNRef, 10*time.Second)
		d.PAM = PAMConfig{
			Enabled: true, MaxTTL: 10 * time.Second, ExpiryInterval: 10 * time.Millisecond,
			Attestors: []attest.Attestor{servedPAMAttestor{}},
			PostgresTargets: []PAMPostgresTarget{{
				TenantID: servedTestTenant, ID: "pg-provider-target", ProviderID: "pam-pg-provider",
				AllowedRoles: []string{"readonly"},
			}},
		}
	})
	startServedExternalCADispatcher(t, h)
	workerCtx, stopWorker := context.WithCancel(context.Background())
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); h.srv.RunPAMSessionExpiry(workerCtx) }()
	t.Cleanup(func() { stopWorker(); <-workerDone })
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "pam-outbox-requester", "access:write", "access:read")
	reviewerOne := seedScopedTokenSubject(t, h.store, h.tenant, "pam-outbox-reviewer-one", "access:approve")
	reviewerTwo := seedScopedTokenSubject(t, h.store, h.tenant, "pam-outbox-reviewer-two", "access:approve")
	issued := servedPAMReviewedOpen(t, h, requester, reviewerOne, reviewerTwo, "pam-provider-backed-postgres", map[string]any{
		"target_type": "postgres", "target_id": "pg-provider-target", "role": "readonly",
		"method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")),
		"ttl_seconds": 5,
	})
	if issued.Postgres == nil {
		t.Fatal("provider-backed PAM did not return one PostgreSQL credential")
	}
	assertPAMPostgresAccess(t, issued.Postgres.DSN, true)
	if !h.hasEvent(t, "dynsecret.lease.pending") || !h.hasEvent(t, "pam.session.started") {
		t.Fatal("provider-backed PAM did not record the durable lease request and session start")
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !pamPostgresRoleExists(t, pgDSN, issued.Postgres.Username) && h.hasEvent(t, "pam.session.expired") {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if pamPostgresRoleExists(t, pgDSN, issued.Postgres.Username) {
		t.Fatal("provider-backed PAM role remained after worker and outbox revocation")
	}
	assertPAMPostgresAccess(t, issued.Postgres.DSN, false)
}

// A PAM request is a proposal, not authority to create a privileged login.
// The first request must leave an approval intent without enqueueing a provider
// grant. A distinct custodian can review that exact intent before activation.
func TestServedPAMRequestDoesNotMintBeforeApproval(t *testing.T) {
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	seedPAMPostgresTable(t, pgDSN)
	adminDSNRef := pamPostgresAdminFileRef(t, pgDSN)
	h := newOperatingServedHarness(t,
		config.Protocols{SSH: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		func(d *Deps) {
			wirePAMPostgresProvider(d, adminDSNRef, time.Minute)
			d.PAM = PAMConfig{
				Enabled: true, MaxTTL: time.Minute, Attestors: []attest.Attestor{servedPAMAttestor{}},
				PostgresTargets: []PAMPostgresTarget{{
					TenantID: servedTestTenant, ID: "approval-pg", ProviderID: "pam-pg-provider",
					AllowedRoles: []string{"readonly"},
				}},
				SSHTargets: []PAMSSHTarget{{
					TenantID: servedTestTenant, ID: "approval-ssh", Host: "127.0.0.1",
					Port: 22, Principals: []string{"alice"},
				}},
			}
		})
	startServedExternalCADispatcher(t, h)
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "pam-approval-requester", "access:write", "access:approve")
	progressReader := seedScopedTokenSubject(t, h.store, h.tenant, "pam-approval-requester", "access:write")
	otherRequester := seedScopedTokenSubject(t, h.store, h.tenant, "pam-other-requester", "access:write")
	reviewerOne := seedScopedTokenSubject(t, h.store, h.tenant, "pam-bound-reviewer-one", "access:approve")
	reviewerTwo := seedScopedTokenSubject(t, h.store, h.tenant, "pam-bound-reviewer-two", "access:approve")
	_, sshPublicKey := generatePAMSSHKey(t)
	for _, tc := range []struct {
		name      string
		requestID string
		body      map[string]any
		effects   []string
	}{
		{"postgres", "e8f4a2d2-782f-4e2d-9da8-01fb2c2d5021",
			map[string]any{"target_type": "postgres", "target_id": "approval-pg", "role": "readonly"},
			[]string{"dynsecret.lease.pending", "pam.session.started"}},
		{"ssh", "2e4abf75-26dc-4cd0-83f8-d08614df914e",
			map[string]any{"target_type": "ssh", "target_id": "approval-ssh", "role": "user",
				"ssh_public_key": sshPublicKey, "ssh_principal": "alice"},
			[]string{"ssh.cert.issued", "pam.session.started"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			approvalsBefore := pamEventCount(t, h, "approval.requested")
			effectCounts := make(map[string]int, len(tc.effects))
			for _, eventType := range tc.effects {
				effectCounts[eventType] = pamEventCount(t, h, eventType)
			}
			tc.body["request_id"] = tc.requestID
			tc.body["reason"] = "on-call production incident 42"
			tc.body["method"] = "stub_pam"
			tc.body["payload_base64"] = base64.StdEncoding.EncodeToString([]byte("genuine"))
			tc.body["ttl_seconds"] = 30
			status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/session-requests", requester,
				"pam-approval-request-"+tc.name, tc.body)
			if status != http.StatusAccepted {
				t.Fatalf("PAM %s request status=%d, want 202 pending approval; body=%s", tc.name, status, body)
			}
			var response map[string]json.RawMessage
			if err := json.Unmarshal(body, &response); err != nil {
				t.Fatalf("decode PAM request response: %v", err)
			}
			if _, hasPostgres := response["postgres"]; hasPostgres {
				t.Fatal("unapproved PAM request exposed a credential")
			}
			if _, hasSSH := response["ssh"]; hasSSH {
				t.Fatal("unapproved PAM request exposed a credential")
			}
			if len(response["approval_request_id"]) == 0 || len(response["intent_digest"]) == 0 {
				t.Fatal("PAM request omitted its exact review identity")
			}
			var pending api.PAMApprovalRequest
			if err := json.Unmarshal(body, &pending); err != nil {
				t.Fatalf("decode exact PAM approval: %v", err)
			}
			progressPath := "/api/v1/access/session-requests/" + pending.ApprovalRequestID
			readProgress := func(wantCount int, wantStatus string) {
				t.Helper()
				code, raw := secretsReq(t, h, http.MethodGet, progressPath, progressReader, nil)
				if code != http.StatusOK {
					t.Fatalf("requester progress status=%d; body=%s", code, raw)
				}
				var progress api.PAMRequestProgress
				if err := json.Unmarshal(raw, &progress); err != nil {
					t.Fatal(err)
				}
				if progress.RequestID != tc.requestID || progress.ApprovalRequestID != pending.ApprovalRequestID ||
					progress.IntentDigest != pending.IntentDigest || progress.ApprovalCount != wantCount || progress.Status != wantStatus {
					t.Fatalf("requester progress = %+v, want count=%d status=%s", progress, wantCount, wantStatus)
				}
				if len(raw) > 0 && (strings.Contains(string(raw), "payload_base64") || strings.Contains(string(raw), "postgres")) {
					t.Fatalf("progress exposed credential or target details: %s", raw)
				}
			}
			readProgress(0, "pending")
			if code, _ := secretsReq(t, h, http.MethodGet, progressPath, otherRequester, nil); code != http.StatusNotFound {
				t.Fatalf("another requester read PAM progress: HTTP %d, want 404", code)
			}
			review, err := h.store.GetOperationApproval(context.Background(), h.tenant, pending.ApprovalRequestID)
			if err != nil {
				t.Fatalf("read PAM reviewer evidence: %v", err)
			}
			if tc.name == "postgres" && !containsExactString(review.EvidenceRefs, "pam-postgres-provider:pam-pg-provider") {
				t.Fatalf("PAM reviewer cannot identify PostgreSQL provider: %v", review.EvidenceRefs)
			}
			if tc.name == "ssh" && (!containsExactString(review.EvidenceRefs, "pam-ssh-host:127.0.0.1:22") || !containsExactString(review.EvidenceRefs, "pam-ssh-principal:alice")) {
				t.Fatalf("PAM reviewer cannot identify SSH host and principal: %v", review.EvidenceRefs)
			}
			status, body = secretsReqKey(t, h, http.MethodPost,
				"/api/v1/approval-requests/"+pending.ApprovalRequestID+"/approvals", requester,
				"pam-self-review-"+tc.name, map[string]any{"intent_digest": pending.IntentDigest})
			if status != http.StatusForbidden {
				t.Fatalf("PAM requester self-approval status=%d, want 403; body=%s", status, body)
			}
			for _, eventType := range tc.effects {
				if pamEventCount(t, h, eventType) != effectCounts[eventType] {
					t.Fatalf("unapproved PAM %s request emitted %s", tc.name, eventType)
				}
			}
			if pamEventCount(t, h, "approval.requested") <= approvalsBefore {
				t.Fatalf("PAM %s request status=%d without an immutable approval intent", tc.name, status)
			}
			tc.body["approval_request_id"] = pending.ApprovalRequestID
			tc.body["intent_digest"] = pending.IntentDigest
			status, _ = secretsReqKey(t, h, http.MethodPost, "/api/v1/access/sessions", requester,
				"pam-unapproved-activation-"+tc.name, tc.body)
			if status == http.StatusCreated {
				t.Fatalf("PAM %s activated without the approved request", tc.name)
			}
			for _, eventType := range tc.effects {
				if pamEventCount(t, h, eventType) != effectCounts[eventType] {
					t.Fatalf("unapproved PAM %s activation emitted %s", tc.name, eventType)
				}
			}
			if tc.name != "postgres" {
				return
			}
			status, body = secretsReqKey(t, h, http.MethodPost,
				"/api/v1/approval-requests/"+pending.ApprovalRequestID+"/approvals", reviewerOne,
				"pam-first-independent-review", map[string]any{"intent_digest": pending.IntentDigest})
			if status != http.StatusOK {
				t.Fatalf("first PAM review status=%d; body=%s", status, body)
			}
			readProgress(1, "pending")
			status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/access/sessions", requester,
				"pam-one-review-is-not-quorum", tc.body)
			if status != http.StatusConflict {
				t.Fatalf("one reviewer activated PAM: status=%d; body=%s", status, body)
			}
			status, body = secretsReqKey(t, h, http.MethodPost,
				"/api/v1/approval-requests/"+pending.ApprovalRequestID+"/approvals", reviewerTwo,
				"pam-second-independent-review", map[string]any{"intent_digest": pending.IntentDigest})
			if status != http.StatusOK {
				t.Fatalf("second PAM review status=%d; body=%s", status, body)
			}
			readProgress(2, "approved")
			changedReason := make(map[string]any, len(tc.body))
			for key, value := range tc.body {
				changedReason[key] = value
			}
			changedReason["reason"] = "a different incident"
			status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/access/sessions", requester,
				"pam-changed-approved-command", changedReason)
			if status != http.StatusForbidden {
				t.Fatalf("changed PAM command status=%d, want 403; body=%s", status, body)
			}
			target := h.srv.pam.postgres[pamTargetID{h.tenant, tc.body["target_id"].(string)}]
			originalProvider := target.cfg.ProviderID
			target.cfg.ProviderID = "swapped-provider"
			status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/access/sessions", requester,
				"pam-changed-reviewed-target", tc.body)
			target.cfg.ProviderID = originalProvider
			if status != http.StatusForbidden {
				t.Fatalf("changed PAM target binding status=%d, want 403; body=%s", status, body)
			}
			originalRevision := target.providerRevision
			target.providerRevision = "restarted-provider-attachment"
			status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/access/sessions", requester,
				"pam-changed-reviewed-provider-revision", tc.body)
			target.providerRevision = originalRevision
			if status != http.StatusForbidden {
				t.Fatalf("changed PAM provider revision status=%d, want 403; body=%s", status, body)
			}
			if pamEventCount(t, h, "dynsecret.lease.pending") != effectCounts["dynsecret.lease.pending"] {
				t.Fatal("a changed or partly reviewed PAM request enqueued a PostgreSQL grant")
			}
			issued := servedPAMOpen(t, h, requester, "pam-exact-approved-activation", tc.body)
			if issued.Postgres == nil || issued.Postgres.DSN == "" {
				t.Fatalf("exact reviewed PAM request did not open PostgreSQL: %+v", issued)
			}
			assertPAMPostgresAccess(t, issued.Postgres.DSN, true)
		})
	}
}

type servedPAMAttestor struct{}

func pamEventCount(t *testing.T, h *servedHarness, eventType string) int {
	t.Helper()
	count := 0
	if err := h.log.Replay(context.Background(), 0, func(e events.Event) error {
		if e.TenantID == h.tenant && e.Type == eventType {
			count++
		}
		return nil
	}); err != nil {
		t.Fatalf("replay PAM event count: %v", err)
	}
	return count
}

func (servedPAMAttestor) Method() string { return "stub_pam" }

func (servedPAMAttestor) Attest(_ context.Context, p []byte) (attest.Attestation, error) {
	if string(p) != "genuine" {
		return attest.Attestation{}, errServedEphemeralForgery
	}
	return attest.Attestation{
		Method:    "stub_pam",
		Subject:   "pam-workload",
		Selectors: []string{"pam:test"},
	}, nil
}

type servedPAMSessionResponse struct {
	ID          string                       `json:"id"`
	TargetID    string                       `json:"target_id"`
	TargetType  string                       `json:"target_type"`
	Status      string                       `json:"status"`
	Subject     string                       `json:"subject"`
	ExpiresAt   time.Time                    `json:"expires_at"`
	Attestation *attest.Attestation          `json:"attestation,omitempty"`
	Postgres    *servedPAMPostgresCredential `json:"postgres,omitempty"`
	SSH         *servedPAMSSHCredential      `json:"ssh,omitempty"`
}

type servedPAMPostgresCredential struct {
	Username string `json:"username"`
	DSN      string `json:"dsn"`
}

type servedPAMSSHCredential struct {
	Certificate string    `json:"certificate"`
	Principal   string    `json:"principal"`
	KeyID       string    `json:"key_id"`
	Serial      uint64    `json:"serial"`
	ValidBefore time.Time `json:"valid_before"`
}

func servedPAMOpen(t *testing.T, h *servedHarness, token, idemKey string, req map[string]any) servedPAMSessionResponse {
	t.Helper()
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/sessions", token, idemKey, req)
	if status != http.StatusCreated {
		t.Fatalf("open PAM session status = %d, want 201; body=%s", status, body)
	}
	var out servedPAMSessionResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode PAM response: %v; body=%s", err, body)
	}
	return out
}

func servedPAMReviewedOpen(t *testing.T, h *servedHarness, requester, reviewerOne, reviewerTwo, idemKey string, req map[string]any) servedPAMSessionResponse {
	t.Helper()
	req["request_id"] = uuid.NewString()
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/session-requests", requester,
		idemKey+"-request", req)
	if status != http.StatusAccepted {
		t.Fatalf("request PAM review status=%d, want 202; body=%s", status, body)
	}
	var pending api.PAMApprovalRequest
	if err := json.Unmarshal(body, &pending); err != nil || pending.ApprovalRequestID == "" || pending.IntentDigest == "" {
		t.Fatalf("decode PAM approval request: %v; body=%s", err, body)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/approval-requests?status=pending", reviewerOne, nil)
	if status != http.StatusOK || !strings.Contains(string(body), pending.ApprovalRequestID) {
		t.Fatalf("PAM reviewer queue status=%d did not include exact request %s; body=%s", status, pending.ApprovalRequestID, body)
	}
	for i, reviewer := range []string{reviewerOne, reviewerTwo} {
		status, body = secretsReqKey(t, h, http.MethodPost,
			"/api/v1/approval-requests/"+pending.ApprovalRequestID+"/approvals", reviewer,
			fmt.Sprintf("%s-review-%d", idemKey, i+1), map[string]any{"intent_digest": pending.IntentDigest})
		if status != http.StatusOK {
			t.Fatalf("PAM independent review %d status=%d; body=%s", i+1, status, body)
		}
	}
	req["approval_request_id"] = pending.ApprovalRequestID
	req["intent_digest"] = pending.IntentDigest
	return servedPAMOpen(t, h, requester, idemKey, req)
}

func startPAMPostgres(t *testing.T) (string, func()) {
	t.Helper()
	port := freePAMPort(t)
	dir, err := os.MkdirTemp("", "trstctl-pam-pg-*")
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	runtime := filepath.Join(dir, "runtime")
	data := filepath.Join(dir, "data")
	for _, path := range []string{bin, runtime, data} {
		if err := os.MkdirAll(path, 0o755); err != nil { // #nosec G301 -- fixture tree in a test tempdir; the mode is part of the fixture (CWE-276)
			t.Fatal(err)
		}
	}
	db := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Username("postgres").Password("postgres").Database("postgres").
		Port(uint32(port)).RuntimePath(runtime).DataPath(data).BinariesPath(bin)) // #nosec G115 -- bounded fixture/corpus value packing inside a test (CWE-190)
	if err := db.Start(); err != nil {
		_ = os.RemoveAll(dir)
		fmt.Fprintln(os.Stderr, "embedded postgres start:", err)
		t.Skip("embedded postgres unavailable")
	}
	return fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres?sslmode=disable", port), func() {
		_ = db.Stop()
		_ = os.RemoveAll(dir)
	}
}

func pamPostgresAdminFileRef(t *testing.T, dsn string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pam-postgres-admin-dsn")
	if err := os.WriteFile(path, []byte(dsn), 0o600); err != nil {
		t.Fatal(err)
	}
	return "file:" + path
}

func wirePAMPostgresProvider(d *Deps, adminDSNRef string, maxTTL time.Duration) {
	cfg := config.DynamicSecretProviderConfig{
		TenantID: servedTestTenant, ID: "pam-pg-provider", Type: "postgresql",
		AdminDSNRef: adminDSNRef, Database: "postgres", Schema: "public",
		UsernamePrefix: "trstctl_pam", AllowedRoles: []string{"readonly"}, MaxTTL: maxTTL.String(),
	}
	provider := newConfiguredDynamicProvider(cfg, map[string]bool{"readonly": true}, maxTTL,
		integrationCredentialResolver{store: d.Store, kek: d.KEK, crypto: d.TenantCrypto}, nil)
	d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {provider}}
}

func seedPAMPostgresTable(t *testing.T, dsn string) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect target postgres: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, `CREATE TABLE public.pam_smoke (id int PRIMARY KEY); INSERT INTO public.pam_smoke VALUES (1);`); err != nil {
		t.Fatalf("seed target postgres: %v", err)
	}
}

func pamPostgresRoleValidUntil(t *testing.T, adminDSN, username string) time.Time {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect target PostgreSQL for role readback: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	var validUntil time.Time
	if err := conn.QueryRow(ctx, `SELECT rolvaliduntil FROM pg_roles WHERE rolname = $1`, username).Scan(&validUntil); err != nil {
		t.Fatalf("read PostgreSQL role native expiry: %v", err)
	}
	return validUntil
}

func assertPAMPostgresAccess(t *testing.T, dsn string, wantOK bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		if wantOK {
			t.Fatalf("connect with PAM postgres credential: %v", err)
		}
		return
	}
	defer func() { _ = conn.Close(context.Background()) }()
	var n int
	err = conn.QueryRow(ctx, `SELECT count(*) FROM public.pam_smoke`).Scan(&n)
	if wantOK && (err != nil || n != 1) {
		t.Fatalf("query with PAM postgres credential: n=%d err=%v", n, err)
	}
	if !wantOK && err == nil {
		t.Fatalf("expired PAM postgres credential still queried target")
	}
}

func pamPostgresRoleExists(t *testing.T, adminDSN, user string) bool {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect target postgres as admin: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=$1)`, user).Scan(&exists); err != nil {
		t.Fatalf("check target postgres role: %v", err)
	}
	return exists
}

func startPAMSSHD(t *testing.T, caPub []byte) pamSSHD {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required for the sshd acceptance backend: %v", err)
	}
	if out, err := pamDockerOutput(t, 15*time.Second, "version", "--format", "{{.Server.Version}}"); err != nil {
		t.Skipf("docker daemon is required for the sshd acceptance backend: %v\n%s", err, out)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "trusted_user_ca_keys"), caPub, 0o644); err != nil { // #nosec G306 -- fixture file in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatalf("write trusted CA: %v", err)
	}
	dockerfile := `FROM alpine:3.20
RUN apk add --no-cache openssh-server
RUN adduser -D -s /bin/sh alice && mkdir -p /etc/ssh/trstctl && ssh-keygen -A
RUN echo 'alice:disabled-password' | chpasswd
COPY trusted_user_ca_keys /etc/ssh/trstctl/trusted_user_ca_keys
RUN printf 'Port 22\nTrustedUserCAKeys /etc/ssh/trstctl/trusted_user_ca_keys\nPasswordAuthentication no\nPubkeyAuthentication yes\nAuthorizedKeysFile none\nPermitRootLogin no\nAllowUsers alice\nLogLevel VERBOSE\n' > /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd","-D","-e","-f","/etc/ssh/sshd_config"]
`
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil { // #nosec G306 -- fixture file in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatalf("write sshd Dockerfile: %v", err)
	}
	image := "trstctl-pam-sshd:" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if out, err := pamDockerOutput(t, 3*time.Minute, "build", "-t", image, dir); err != nil {
		t.Skipf("build sshd container image: %v\n%s", err, out)
	}
	t.Cleanup(func() { pamDockerCleanup("image", "rm", "-f", image) })
	name := "trstctl-pam-sshd-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if out, err := pamDockerOutput(t, 30*time.Second, "run", "-d", "--name", name, "-p", "127.0.0.1::22", image); err != nil {
		t.Fatalf("run sshd container: %v\n%s", err, out)
	}
	t.Cleanup(func() { pamDockerCleanup("rm", "-f", name) })
	var addr string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		out, err := pamDockerOutput(t, 5*time.Second, "port", name, "22/tcp")
		if err == nil {
			addr = strings.TrimSpace(string(out))
			if addr != "" {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if addr == "" {
		logs, _ := pamDockerOutput(t, 15*time.Second, "logs", name)
		t.Fatalf("sshd container did not expose a port; logs:\n%s", logs)
	}
	parts := strings.Split(addr, ":")
	port, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		t.Fatalf("parse sshd port from %q: %v", addr, err)
	}
	return pamSSHD{Name: name, Port: port}
}

func pamDockerOutput(t *testing.T, timeout time.Duration, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput() // #nosec G204 -- fixed Docker test-harness operations bounded by a context deadline (CWE-78)
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("docker %s exceeded %s; the daemon may be unresponsive", strings.Join(args, " "), timeout)
	}
	return out, err
}

func pamDockerCleanup(args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "docker", args...).Run() // #nosec G204 -- fixed best-effort test cleanup bounded by a context deadline (CWE-78)
}

type pamSSHD struct {
	Name string
	Port int
}

func generatePAMSSHKey(t *testing.T) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skipf("ssh-keygen is required for the sshd acceptance backend: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", keyPath, "-C", "pam-01").CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Fatalf("generate SSH user key: %v\n%s", err, out)
	}
	pub, err := os.ReadFile(keyPath + ".pub") // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatalf("read SSH public key: %v", err)
	}
	return keyPath, string(pub)
}

func assertPAMSSHAccess(t *testing.T, sshd pamSSHD, keyPath, cert string, wantOK bool) {
	t.Helper()
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skipf("ssh client is required for the sshd acceptance backend: %v", err)
	}
	certPath := keyPath + "-cert.pub"
	if err := os.WriteFile(certPath, []byte(cert), 0o600); err != nil {
		t.Fatalf("write SSH certificate: %v", err)
	}
	args := []string{
		"-F", "/dev/null",
		"-i", keyPath,
		"-o", "CertificateFile=" + certPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", "BatchMode=yes",
		"-p", strconv.Itoa(sshd.Port),
		"alice@127.0.0.1",
		"true",
	}
	cmd := exec.Command("ssh", args...) // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	out, err := cmd.CombinedOutput()
	if wantOK && err != nil {
		logs, _ := pamDockerOutput(t, 15*time.Second, "logs", sshd.Name)
		t.Fatalf("ssh with PAM certificate failed: %v\n%s\nsshd logs:\n%s", err, out, logs)
	}
	if !wantOK && err == nil {
		t.Fatalf("expired PAM SSH certificate still authenticated")
	}
}

func freePAMPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}
