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

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A process can die after the signer returns a valid certificate but before
// pam.session.started is durable. This test captures that exact cert, verifies
// it works on stock sshd, then proves the recovery KRL rejects it. The live
// replica fence must keep the worker from revoking a still-running signer call.
func TestServedPAMSSHCrashAfterSignRecoversByKeyID(t *testing.T) {
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
	requestID := uuid.NewString()
	body := map[string]any{
		"request_id": requestID, "target_type": "ssh", "target_id": "ssh-edge",
		"role": "user", "reason": "crash-boundary drill", "method": "stub_pam",
		"payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")),
		"ssh_public_key": publicKey, "ssh_principal": "alice", "ttl_seconds": 120,
	}
	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/session-requests", requester, "pam-crash-request", body)
	if status != http.StatusAccepted {
		t.Fatalf("request status %d: %s", status, raw)
	}
	var pending api.PAMApprovalRequest
	if err := json.Unmarshal(raw, &pending); err != nil {
		t.Fatal(err)
	}
	for i, reviewer := range []string{reviewerOne, reviewerTwo} {
		status, raw = secretsReqKey(t, h, http.MethodPost,
			"/api/v1/approval-requests/"+pending.ApprovalRequestID+"/approvals", reviewer,
			"pam-crash-approval-"+string(rune('1'+i)), map[string]any{"intent_digest": pending.IntentDigest})
		if status != http.StatusOK {
			t.Fatalf("approval %d status %d: %s", i+1, status, raw)
		}
	}
	body["approval_request_id"] = pending.ApprovalRequestID
	body["intent_digest"] = pending.IntentDigest
	var signedCert string
	var serial uint64
	h.srv.pam.afterSSHSign = func(cert []byte, issuedSerial uint64) error {
		signedCert, serial = string(cert), issuedSerial
		return errors.New("injected process loss after signer return")
	}
	status, _ = secretsReqKey(t, h, http.MethodPost, "/api/v1/access/sessions", requester, "pam-crash-activate", body)
	if status < 500 || signedCert == "" || serial == 0 {
		t.Fatalf("crash edge status=%d cert-present=%t serial=%d", status, signedCert != "", serial)
	}
	sessionID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl-pam-session\x00"+h.tenant+"\x00pam-crash-activate")).String()
	if _, err := h.store.GetPAMSession(context.Background(), h.tenant, sessionID); !store.IsNotFound(err) {
		t.Fatalf("crashed SSH signer created a session: %v", err)
	}
	intent, err := h.store.GetPAMSSHActivation(context.Background(), h.tenant, sessionID)
	if err != nil || intent.Status != "pending" || intent.KeyID != "pam:"+sessionID {
		t.Fatalf("durable pre-sign intent = %+v, %v", intent, err)
	}
	if _, err := h.store.GetPAMSSHActivation(context.Background(), "22222222-2222-2222-2222-222222222222", sessionID); !store.IsNotFound(err) {
		t.Fatalf("foreign tenant read a PAM signing intent: %v", err)
	}
	assertPAMSSHAccess(t, sshd, keyPath, signedCert, true)
	acquired, err := h.store.WithPAMSSHActivationFence(context.Background(), h.tenant, sessionID, func() error {
		if err := h.srv.pam.recoverIncompleteSSHActivations(context.Background()); err != nil {
			return err
		}
		held, err := h.store.GetPAMSSHActivation(context.Background(), h.tenant, sessionID)
		if err != nil || held.Status != "pending" {
			t.Fatalf("active signer was revoked: %+v, %v", held, err)
		}
		return nil
	})
	if err != nil || !acquired {
		t.Fatalf("signer fence: acquired=%t err=%v", acquired, err)
	}
	// A crash after the recovery intent is also replayable: it remains
	// revoking until KRL synchronization and the terminal event complete.
	if err := h.srv.pam.appendSSHRecoveryEvent(context.Background(), intent, projections.EventPAMSSHSigningRecoveryRequested); err != nil {
		t.Fatal(err)
	}
	intent, err = h.store.GetPAMSSHActivation(context.Background(), h.tenant, sessionID)
	if err != nil || intent.Status != "revoking" {
		t.Fatalf("recovery intent = %+v, %v", intent, err)
	}
	if err := h.srv.pam.recoverIncompleteSSHActivations(context.Background()); err != nil {
		t.Fatal(err)
	}
	intent, err = h.store.GetPAMSSHActivation(context.Background(), h.tenant, sessionID)
	if err != nil || intent.Status != "recovered" {
		t.Fatalf("settled recovery = %+v, %v", intent, err)
	}
	if !h.srv.protocols.ssh.krl.IsRevoked(0, intent.KeyID) {
		t.Fatal("KRL does not revoke the orphaned signer key ID")
	}
	if pamEventCount(t, h, projections.EventPAMSSHSigningRecoveryRequested) != 1 ||
		pamEventCount(t, h, projections.EventPAMSSHSigningRecovered) != 1 {
		t.Fatal("recovery did not record one request and one confirmed result")
	}
	restored, err := newSSHProtocol(h.srv.protocols.ssh.ca, h.tenant, h.srv.protocols.ssh.guard, h.srv)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.restoreRevocations(context.Background(), h.log); err != nil {
		t.Fatal(err)
	}
	if !restored.krl.IsRevoked(0, intent.KeyID) {
		t.Fatal("cold KRL replay lost recovered key ID")
	}
	krlPath := filepath.Join(t.TempDir(), "recovered.krl")
	if err := os.WriteFile(krlPath, restored.KRLBytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := pamDockerOutput(t, 10*time.Second, "cp", krlPath, sshd.Name+":/etc/ssh/trstctl/revoked.krl"); err != nil {
		t.Fatalf("install KRL: %v: %s", err, out)
	}
	if out, err := pamDockerOutput(t, 10*time.Second, "exec", sshd.Name, "sh", "-c", "printf 'RevokedKeys /etc/ssh/trstctl/revoked.krl\\n' >> /etc/ssh/sshd_config && /usr/sbin/sshd -t && kill -HUP 1"); err != nil {
		t.Fatalf("enable KRL: %v: %s", err, out)
	}
	assertPAMSSHAccess(t, sshd, keyPath, signedCert, false)
	h.srv.pam.afterSSHSign = nil
	issuedBefore := pamEventCount(t, h, "ssh.cert.issued")
	status, _ = secretsReqKey(t, h, http.MethodPost, "/api/v1/access/sessions", requester, "pam-crash-activate-retry", body)
	if status < 400 {
		t.Fatalf("aborted approval reopened a session: %d", status)
	}
	if after := pamEventCount(t, h, "ssh.cert.issued"); after != issuedBefore {
		t.Fatalf("retry minted %d more certificates", after-issuedBefore)
	}
	// A different reviewed request cannot reuse the old idempotency key while
	// its first attempt has no pam_sessions row. The activation projection is
	// the durable guard across result-cache expiry and process restart.
	_, err = h.srv.pam.OpenPAMSession(context.Background(), h.tenant, "pam-crash-activate", "pam-requester", api.PAMSessionRequest{
		RequestID: uuid.NewString(), ApprovalRequestID: uuid.NewString(), IntentDigest: "sha256:fresh-review",
		TargetType: "ssh", TargetID: "ssh-edge", Role: "user", Reason: "second attempt",
		Method: "stub_pam", Payload: []byte("genuine"), SSHPublicKey: []byte(publicKey),
		SSHPrincipal: "alice", TTLSeconds: 120,
	})
	if !errors.Is(err, orchestrator.ErrIdempotencyConflict) {
		t.Fatalf("old idempotency key reused after crash: %v", err)
	}
	if h.logContains(t, signedCert) {
		t.Fatal("one-time SSH certificate leaked into event log")
	}
}

// If the start event reached JetStream but its projection acknowledgement was
// lost, recovery must finish that event rather than revoke an active session.
func TestPAMSSHRecoveryFinishesUnacknowledgedStartEvent(t *testing.T) {
	h := newOperatingServedHarness(t,
		config.Protocols{SSH: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}},
		func(d *Deps) {
			d.PAM = PAMConfig{Enabled: true, Attestors: []attest.Attestor{servedPAMAttestor{}},
				SSHTargets: []PAMSSHTarget{{TenantID: servedTestTenant, ID: "ssh-edge", Host: "127.0.0.1", Port: 22, Principals: []string{"alice"}}}}
		})
	ctx := context.Background()
	sessionID, requestID := uuid.NewString(), uuid.NewString()
	now := time.Now().UTC()
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return h.store.ApplyPAMSSHActivationRequestedTx(ctx, tx, h.tenant, sessionID, requestID, now)
	}); err != nil {
		t.Fatal(err)
	}
	start := projections.PAMSessionStarted{
		ID: sessionID, TargetType: "ssh", TargetID: "ssh-edge", Role: "user",
		Status: "active", Subject: "pam-workload", RequestedBy: "pam-requester",
		SSHKeyID: "pam:" + sessionID, SSHSerial: 42,
		IdempotencyKey: "ack-lost", StartedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	data, err := json.Marshal(start)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.log.Append(ctx, events.Event{
		ID: pamSSHStartedEventID(h.tenant, sessionID), Type: projections.EventPAMSessionStarted,
		TenantID: h.tenant, Data: data,
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.pam.recoverIncompleteSSHActivations(ctx); err != nil {
		t.Fatal(err)
	}
	intent, err := h.store.GetPAMSSHActivation(ctx, h.tenant, sessionID)
	if err != nil || intent.Status != "completed" {
		t.Fatalf("unacknowledged start was not projected: %+v, %v", intent, err)
	}
	if session, err := h.store.GetPAMSession(ctx, h.tenant, sessionID); err != nil || session.Status != "active" {
		t.Fatalf("unacknowledged session did not survive: %+v, %v", session, err)
	}
	if h.srv.protocols.ssh.krl.IsRevoked(0, start.SSHKeyID) ||
		pamEventCount(t, h, projections.EventPAMSSHSigningRecoveryRequested) != 0 {
		t.Fatal("recovery revoked a session whose start event was already durable")
	}
}
