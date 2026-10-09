// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

func TestServedPAMTenantTargetRegistrationAndDisable(t *testing.T) {
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	seedPAMPostgresTable(t, pgDSN)
	adminDSNRef := pamPostgresAdminFileRef(t, pgDSN)
	h := newOperatingServedHarness(t, config.Protocols{SSH: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}}, func(d *Deps) {
		wirePAMPostgresProvider(d, adminDSNRef, time.Minute)
		d.PAM = PAMConfig{Enabled: true, MaxTTL: time.Minute, Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	startServedExternalCADispatcher(t, h)
	registrar := seedScopedTokenSubject(t, h.store, h.tenant, "pam-target-registrar", "access:read", "access:targets.write")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "pam-target-requester", "access:read", "access:write")
	reviewerOne := seedScopedTokenSubject(t, h.store, h.tenant, "pam-target-reviewer-one", "access:approve")
	reviewerTwo := seedScopedTokenSubject(t, h.store, h.tenant, "pam-target-reviewer-two", "access:approve")
	input := map[string]any{"id": "tenant-pg", "target_type": "postgres", "provider_id": "pam-pg-provider", "allowed_roles": []string{"readonly"}}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/targets", requester, "target-requester-denied", input)
	if status != http.StatusForbidden {
		t.Fatalf("requester registered target: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/access/targets", registrar, "target-register", input)
	if status != http.StatusCreated {
		t.Fatalf("register target: %d %s", status, body)
	}
	var registered api.PAMTarget
	if err := json.Unmarshal(body, &registered); err != nil {
		t.Fatal(err)
	}
	if registered.ID != "tenant-pg" || registered.Source != "tenant" || !registered.Enabled || registered.RegisteredBy != "pam-target-registrar" {
		t.Fatalf("registration readback: %+v", registered)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/access/targets", registrar, "target-register-different-key", input)
	if status != http.StatusConflict {
		t.Fatalf("duplicate target registration: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodGet, "/api/v1/access/targets/postgres/tenant-pg", registrar, "", nil)
	if status != http.StatusOK {
		t.Fatalf("get target: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodGet, "/api/v1/access/targets", registrar, "", nil)
	if status != http.StatusOK || !containsTarget(body, "tenant-pg") {
		t.Fatalf("list target: %d %s", status, body)
	}
	if !h.hasEvent(t, "pam.target.registered") {
		t.Fatal("registration lacked immutable audit event")
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/access/targets", registrar, "target-bad-provider", map[string]any{"id": "bad-pg", "target_type": "postgres", "provider_id": "other", "allowed_roles": []string{"readonly"}})
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("accepted missing provider: %d %s", status, body)
	}
	otherTenant := "22222222-2222-2222-2222-222222222222"
	if err := h.store.UpsertTenant(context.Background(), store.Tenant{TenantID: otherTenant, Name: "PAM target foreign tenant"}); err != nil {
		t.Fatal(err)
	}
	foreign := seedScopedTokenSubject(t, h.store, otherTenant, "pam-target-foreign", "access:read")
	status, body = secretsReqKey(t, h, http.MethodGet, "/api/v1/access/targets/postgres/tenant-pg", foreign, "", nil)
	if status != http.StatusNotFound {
		t.Fatalf("foreign tenant saw target: %d %s", status, body)
	}
	issued := servedPAMReviewedOpen(t, h, requester, reviewerOne, reviewerTwo, "tenant-registered-pg", map[string]any{
		"request_id": uuid.NewString(), "target_type": "postgres", "target_id": "tenant-pg", "role": "readonly",
		"method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")), "ttl_seconds": 30,
	})
	if issued.Postgres == nil {
		t.Fatal("registered target did not issue a credential")
	}
	assertPAMPostgresAccess(t, issued.Postgres.DSN, true)
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/access/targets/postgres/tenant-pg/disable", registrar, "target-disable", map[string]any{"reason": "retire test target"})
	if status != http.StatusOK {
		t.Fatalf("disable target: %d %s", status, body)
	}
	if err := json.Unmarshal(body, &registered); err != nil || registered.Enabled || registered.DisabledAt == nil {
		t.Fatalf("disable readback: %v %+v", err, registered)
	}
	if !h.hasEvent(t, "pam.target.disabled") {
		t.Fatal("disable lacked immutable audit event")
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/access/session-requests", requester, "target-disabled-request", map[string]any{
		"request_id": uuid.NewString(), "target_type": "postgres", "target_id": "tenant-pg", "role": "readonly",
		"method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")),
	})
	if status != http.StatusForbidden {
		t.Fatalf("disabled target accepted request: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/access/sessions/"+issued.ID+"/revoke", requester, "target-old-session-revoke", map[string]any{"reason": "retire old grant"})
	if status != http.StatusAccepted {
		t.Fatalf("disabled target stranded old session: %d %s", status, body)
	}

	sshInput := map[string]any{"id": "tenant-ssh", "target_type": "ssh", "host": "127.0.0.1", "port": 22, "principals": []string{"alice"}}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/access/targets", registrar, "ssh-target-register", sshInput)
	if status != http.StatusCreated {
		t.Fatalf("register SSH target: %d %s", status, body)
	}
	if err := json.Unmarshal(body, &registered); err != nil || registered.TargetType != "ssh" || registered.Host != "127.0.0.1" || registered.Port != 22 {
		t.Fatalf("SSH registration readback: %v %+v", err, registered)
	}
	_, publicKey := generatePAMSSHKey(t)
	sshSession := servedPAMReviewedOpen(t, h, requester, reviewerOne, reviewerTwo, "tenant-registered-ssh", map[string]any{
		"request_id": uuid.NewString(), "target_type": "ssh", "target_id": "tenant-ssh", "role": "user",
		"method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")),
		"ssh_public_key": publicKey, "ssh_principal": "alice", "ttl_seconds": 30,
	})
	if sshSession.SSH == nil || sshSession.SSH.Certificate == "" || sshSession.SSH.KeyID != "pam:"+sshSession.ID {
		t.Fatalf("registered SSH target did not sign its approved session: %+v", sshSession)
	}
}

func containsTarget(body []byte, id string) bool {
	var list struct {
		Items []api.PAMTarget `json:"items"`
	}
	if json.Unmarshal(body, &list) != nil {
		return false
	}
	for _, target := range list.Items {
		if target.ID == id {
			return true
		}
	}
	return false
}
