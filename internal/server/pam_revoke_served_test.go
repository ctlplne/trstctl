// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// An emergency revocation must close the native PostgreSQL role before its
// reviewed TTL, not merely change the control-plane session label.
func TestServedPAMEarlyRevokePostgres(t *testing.T) {
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	seedPAMPostgresTable(t, pgDSN)
	adminDSNRef := pamPostgresAdminFileRef(t, pgDSN)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		wirePAMPostgresProvider(d, adminDSNRef, time.Minute)
		d.PAM = PAMConfig{
			Enabled: true, DefaultTTL: 30 * time.Second, MaxTTL: time.Minute,
			ExpiryInterval: 10 * time.Millisecond,
			Attestors:      []attest.Attestor{servedPAMAttestor{}},
			PostgresTargets: []PAMPostgresTarget{{
				TenantID: servedTestTenant, ID: "pg-main", ProviderID: "pam-pg-provider",
				AllowedRoles: []string{"readonly"},
			}},
		}
	})
	startServedExternalCADispatcher(t, h)
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "pam-requester", "access:read", "access:write")
	readOnly := seedScopedTokenSubject(t, h.store, h.tenant, "pam-observer", "access:read")
	reviewerOne := seedScopedTokenSubject(t, h.store, h.tenant, "pam-reviewer-one", "access:approve")
	reviewerTwo := seedScopedTokenSubject(t, h.store, h.tenant, "pam-reviewer-two", "access:approve")
	issued := servedPAMReviewedOpen(t, h, requester, reviewerOne, reviewerTwo, "pam-early-revoke-pg", map[string]any{
		"target_type": "postgres", "target_id": "pg-main", "role": "readonly",
		"reason": "test approved use", "method": "stub_pam",
		"payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")),
		"ttl_seconds":    30,
	})
	if issued.Postgres == nil || issued.Postgres.DSN == "" {
		t.Fatalf("PAM issuance returned no PostgreSQL credential: %+v", issued)
	}
	assertPAMPostgresAccess(t, issued.Postgres.DSN, true)

	foreignTenant := "22222222-2222-2222-2222-222222222222"
	if err := h.store.UpsertTenant(context.Background(), store.Tenant{TenantID: foreignTenant, Name: "foreign PAM tenant"}); err != nil {
		t.Fatal(err)
	}
	foreign := seedScopedTokenSubject(t, h.store, foreignTenant, "foreign-revoker", "access:write")
	path := "/api/v1/access/sessions/" + issued.ID + "/revoke"
	if code, _ := secretsReqKey(t, h, http.MethodPost, path, readOnly, "observer-revoke", map[string]any{"reason": "not authorized"}); code != http.StatusForbidden {
		t.Fatalf("read-only PAM revoker returned %d, want 403", code)
	}
	if code, _ := secretsReqKey(t, h, http.MethodPost, path, foreign, "foreign-revoke", map[string]any{"reason": "foreign"}); code != http.StatusNotFound {
		t.Fatalf("cross-tenant PAM revoke returned %d, want 404", code)
	}
	if code, _ := secretsReqKey(t, h, http.MethodPost, path, requester, "missing-reason", map[string]any{}); code != http.StatusUnprocessableEntity {
		t.Fatalf("PAM revoke without reason returned %d, want 422", code)
	}
	code, body := secretsReqKey(t, h, http.MethodPost, path, requester, "revoke-pg-once", map[string]any{"reason": "incident containment"})
	if code != http.StatusAccepted {
		t.Fatalf("PAM revoke returned %d, want 202: %s", code, body)
	}
	var queued struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &queued); err != nil || queued.Status != "revoking" {
		t.Fatalf("PAM revoke queued result = %+v, err = %v", queued, err)
	}
	if replayCode, replay := secretsReqKey(t, h, http.MethodPost, path, requester, "revoke-pg-once", map[string]any{"reason": "incident containment"}); replayCode != code || string(replay) != string(body) {
		t.Fatalf("exact revoke retry changed response: %d %s", replayCode, replay)
	}
	if code, _ := secretsReqKey(t, h, http.MethodPost, path, requester, "second-revoke", map[string]any{"reason": "different incident"}); code != http.StatusConflict {
		t.Fatalf("second reason for already revoking PAM session returned %d, want 409", code)
	}

	workerCtx, cancel := context.WithCancel(context.Background())
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); h.srv.RunPAMSessionExpiry(workerCtx) }()
	defer func() { cancel(); <-workerDone }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !pamPostgresRoleExists(t, pgDSN, issued.Postgres.Username) {
			code, body = secretsReq(t, h, http.MethodGet, "/api/v1/access/sessions/"+issued.ID, requester, nil)
			if code == http.StatusOK {
				var settled struct {
					Status string `json:"status"`
				}
				if json.Unmarshal(body, &settled) == nil && settled.Status == "revoked" {
					assertPAMPostgresAccess(t, issued.Postgres.DSN, false)
					if n := pamEventCount(t, h, "pam.session.revocation_requested"); n != 1 {
						t.Fatalf("revocation request events = %d, want one", n)
					}
					if n := pamEventCount(t, h, "pam.session.revoked"); n != 1 {
						t.Fatalf("revocation completed events = %d, want one", n)
					}
					return
				}
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("PAM session %s did not revoke the native role and settle before its TTL", issued.ID)
}

func TestServedPAMProviderRemovalFailureAndRetry(t *testing.T) {
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	seedPAMPostgresTable(t, pgDSN)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		wirePAMPostgresProvider(d, pamPostgresAdminFileRef(t, pgDSN), 5*time.Minute)
		d.PAM = PAMConfig{
			Enabled: true, DefaultTTL: 3 * time.Minute, MaxTTL: 5 * time.Minute,
			Attestors:       []attest.Attestor{servedPAMAttestor{}},
			PostgresTargets: []PAMPostgresTarget{{TenantID: servedTestTenant, ID: "pg-main", ProviderID: "pam-pg-provider", AllowedRoles: []string{"readonly"}}},
		}
	})
	// Serve issuance, then pause only this harness's dispatcher so the first
	// revoke outbox row can be driven to a real terminal provider outcome.
	dispatchCtx, cancelDispatch := context.WithCancel(context.Background())
	dispatchDone := make(chan struct{})
	go func() { defer close(dispatchDone); h.srv.RunDispatcher(dispatchCtx) }()
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "pam-requester", "access:read", "access:write")
	reviewerOne := seedScopedTokenSubject(t, h.store, h.tenant, "pam-reviewer-one", "access:approve")
	reviewerTwo := seedScopedTokenSubject(t, h.store, h.tenant, "pam-reviewer-two", "access:approve")
	issued := servedPAMReviewedOpen(t, h, requester, reviewerOne, reviewerTwo, "pam-revoke-retry", map[string]any{
		"target_type": "postgres", "target_id": "pg-main", "role": "readonly",
		"reason": "approved use", "method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")), "ttl_seconds": 180,
	})
	cancelDispatch()
	<-dispatchDone
	assertPAMPostgresAccess(t, issued.Postgres.DSN, true)
	path := "/api/v1/access/sessions/" + issued.ID + "/revoke"
	if code, body := secretsReqKey(t, h, http.MethodPost, path, requester, "revoke-first", map[string]any{"reason": "incident"}); code != http.StatusAccepted {
		t.Fatalf("first revoke status %d: %s", code, body)
	}
	if err := h.srv.pam.expireOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	rec, err := h.store.GetPAMSession(context.Background(), h.tenant, issued.ID)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := h.store.GetDynamicSecretLease(context.Background(), h.tenant, rec.BackendRef)
	if err != nil || lease.RevokeOutboxID == nil {
		t.Fatalf("first provider removal not queued: %+v, %v", lease, err)
	}
	first, err := h.srv.outbox.Get(context.Background(), h.tenant, *lease.RevokeOutboxID)
	if err != nil {
		t.Fatal(err)
	}
	message := orchestrator.Message{ID: first.ID, TenantID: h.tenant, Destination: first.Destination, IdempotencyKey: first.IdempotencyKey, Payload: first.Payload, Attempts: 10}
	dispatcher := h.srv.obHandler.(*issuanceDispatcher).secretIntegrations
	if handled, err := dispatcher.DeliverTerminalFailure(context.Background(), message, errors.New("provider unavailable")); !handled || err != nil {
		t.Fatalf("terminal provider failure: handled=%t err=%v", handled, err)
	}
	if err := h.srv.pam.expireOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	code, body := secretsReq(t, h, http.MethodGet, "/api/v1/access/sessions/"+issued.ID, requester, nil)
	var failed struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &failed); err != nil || code != http.StatusOK || failed.Status != "revocation_failed" {
		t.Fatalf("PAM did not expose provider failure: code=%d body=%s err=%v", code, body, err)
	}
	assertPAMPostgresAccess(t, issued.Postgres.DSN, true)
	if err := projections.New(h.store).Rebuild(context.Background(), h.log); err != nil {
		t.Fatalf("cold replay terminal PAM failure: %v", err)
	}
	if replayed, err := h.store.GetPAMSession(context.Background(), h.tenant, issued.ID); err != nil || replayed.Status != store.PAMSessionStatusRevocationFailed {
		t.Fatalf("cold replay lost PAM failure: %+v, %v", replayed, err)
	}
	retryBody := map[string]any{"reason": "repair complete, retry removal"}
	retryCode, retryResponse := secretsReqKey(t, h, http.MethodPost, path, requester, "revoke-retry-after-repair", retryBody)
	if retryCode != http.StatusAccepted {
		t.Fatalf("retry revoke status %d: %s", retryCode, retryResponse)
	}
	if code, body := secretsReqKey(t, h, http.MethodPost, path, requester, "revoke-retry-after-repair", retryBody); code != retryCode || string(body) != string(retryResponse) {
		t.Fatalf("exact retry replay changed result: code=%d body=%s", code, body)
	}
	if code, _ := secretsReqKey(t, h, http.MethodPost, path, requester, "parallel-retry", retryBody); code != http.StatusConflict {
		t.Fatalf("new command while retry is pending returned %d, want conflict", code)
	}
	if err := h.srv.pam.expireOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	retried, err := h.store.GetDynamicSecretLease(context.Background(), h.tenant, rec.BackendRef)
	if err != nil || retried.RevokeOutboxID == nil || *retried.RevokeOutboxID == first.ID {
		t.Fatalf("retry did not queue a new exact provider command: %+v, %v", retried, err)
	}
	second, err := h.srv.outbox.Get(context.Background(), h.tenant, *retried.RevokeOutboxID)
	if err != nil {
		t.Fatal(err)
	}
	secondMessage := orchestrator.Message{ID: second.ID, TenantID: h.tenant, Destination: second.Destination, IdempotencyKey: second.IdempotencyKey, Payload: second.Payload, Attempts: 1}
	if handled, err := dispatcher.Deliver(context.Background(), secondMessage); !handled || err != nil {
		t.Fatalf("dispatch repaired provider removal: handled=%t err=%v", handled, err)
	}
	if err := h.srv.pam.expireOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	code, body = secretsReq(t, h, http.MethodGet, "/api/v1/access/sessions/"+issued.ID, requester, nil)
	var done struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &done); err != nil || code != http.StatusOK || done.Status != "revoked" {
		t.Fatalf("PAM did not confirm repaired removal: code=%d body=%s err=%v", code, body, err)
	}
	assertPAMPostgresAccess(t, issued.Postgres.DSN, false)
	if err := projections.New(h.store).Rebuild(context.Background(), h.log); err != nil {
		t.Fatalf("cold replay completed PAM retry: %v", err)
	}
	if replayed, err := h.store.GetPAMSession(context.Background(), h.tenant, issued.ID); err != nil || replayed.Status != store.PAMSessionStatusRevoked {
		t.Fatalf("cold replay lost repaired PAM removal: %+v, %v", replayed, err)
	}
}

func TestServedPAMEarlyRevokeSSHThroughKRL(t *testing.T) {
	h := newOperatingServedHarness(t,
		config.Protocols{SSH: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		func(d *Deps) {
			d.PAM = PAMConfig{Enabled: true, DefaultTTL: 2 * time.Minute, MaxTTL: 3 * time.Minute,
				ExpiryInterval: 10 * time.Millisecond, Attestors: []attest.Attestor{servedPAMAttestor{}},
				SSHTargets: []PAMSSHTarget{{TenantID: servedTestTenant, ID: "ssh-edge", Host: "127.0.0.1", Port: 22, Principals: []string{"alice"}}}}
		})
	caPub, err := h.srv.protocols.ssh.AuthorityKey()
	if err != nil {
		t.Fatal(err)
	}
	sshd := startPAMSSHD(t, caPub)
	keyPath, publicKey := generatePAMSSHKey(t)
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "pam-requester", "access:read", "access:write")
	reviewerOne := seedScopedTokenSubject(t, h.store, h.tenant, "pam-reviewer-one", "access:approve")
	reviewerTwo := seedScopedTokenSubject(t, h.store, h.tenant, "pam-reviewer-two", "access:approve")
	issued := servedPAMReviewedOpen(t, h, requester, reviewerOne, reviewerTwo, "pam-early-revoke-ssh", map[string]any{
		"target_type": "ssh", "target_id": "ssh-edge", "role": "user", "reason": "approved incident access",
		"method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")),
		"ssh_public_key": publicKey, "ssh_principal": "alice", "ttl_seconds": 120,
	})
	if issued.SSH == nil {
		t.Fatal("PAM SSH certificate was not issued")
	}
	assertPAMSSHAccess(t, sshd, keyPath, issued.SSH.Certificate, true)
	path := "/api/v1/access/sessions/" + issued.ID + "/revoke"
	code, body := secretsReqKey(t, h, http.MethodPost, path, requester, "revoke-ssh-once", map[string]any{"reason": "incident containment"})
	if code != http.StatusAccepted {
		t.Fatalf("PAM SSH revoke status %d: %s", code, body)
	}
	var queued struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &queued); err != nil || queued.Status != "revoking" {
		t.Fatalf("PAM SSH queued state %+v: %v", queued, err)
	}
	workerCtx, cancel := context.WithCancel(context.Background())
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); h.srv.RunPAMSessionExpiry(workerCtx) }()
	defer func() { cancel(); <-workerDone }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		current, err := h.srv.GetPAMSession(context.Background(), h.tenant, issued.ID)
		if err == nil && current.Status == "revoked" {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	current, err := h.srv.GetPAMSession(context.Background(), h.tenant, issued.ID)
	if err != nil || current.Status != "revoked" {
		t.Fatalf("PAM SSH session did not reach revoked state before TTL: %+v, %v", current, err)
	}
	restored, err := newSSHProtocol(h.srv.protocols.ssh.ca, h.tenant, h.srv.protocols.ssh.guard, h.srv)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.restoreRevocations(context.Background(), h.log); err != nil {
		t.Fatalf("cold replay PAM KRL: %v", err)
	}
	if !restored.krl.IsRevoked(issued.SSH.Serial, issued.SSH.KeyID) {
		t.Fatal("cold replay lost the exact PAM SSH certificate revocation")
	}
	krlPath := filepath.Join(t.TempDir(), "revoked.krl")
	if err := os.WriteFile(krlPath, restored.KRLBytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := pamDockerOutput(t, 10*time.Second, "cp", krlPath, sshd.Name+":/etc/ssh/trstctl/revoked.krl"); err != nil {
		t.Fatalf("install product KRL: %v: %s", err, out)
	}
	if out, err := pamDockerOutput(t, 10*time.Second, "exec", sshd.Name, "sh", "-c", "printf 'RevokedKeys /etc/ssh/trstctl/revoked.krl\\n' >> /etc/ssh/sshd_config && /usr/sbin/sshd -t && kill -HUP 1"); err != nil {
		t.Fatalf("enable product KRL on sshd: %v: %s", err, out)
	}
	assertPAMSSHAccess(t, sshd, keyPath, issued.SSH.Certificate, false)
	if n := pamEventCount(t, h, "pam.session.revocation_requested"); n != 1 {
		t.Fatalf("PAM SSH request events = %d", n)
	}
	if n := pamEventCount(t, h, "pam.session.revoked"); n != 1 {
		t.Fatalf("PAM SSH completed events = %d", n)
	}
}
