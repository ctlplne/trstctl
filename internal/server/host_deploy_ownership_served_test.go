// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// A host-executed first issuance (executor: agent) runs on the host before the
// lifecycle reaches deployed. The ownership-readiness gate that guards the
// deployed edge must therefore refuse at the deploy call, before any key is
// generated or any job is handed to the host, and say why. The same call must
// pass once the owner has attested.
func TestServedHostDeployRefusesUnattestedOwnerBeforeDispatch(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		withAgentChannel(d)
		d.AgentClaimableJobKinds = []string{"endpoint.renew", "connector.deploy"}
		d.OwnershipAttestationCadence = 90 * 24 * time.Hour
	})
	admin := seedScopedToken(t, h.store, h.tenant, "owners:write", "connectors:write", "certs:issue", "identities:write", "identities:read")
	create := func(path string, request any) string {
		t.Helper()
		code, body := secretsReq(t, h, http.MethodPost, path, admin, request)
		if code != http.StatusCreated {
			t.Fatalf("prepare %s: status=%d body=%s", path, code, body)
		}
		var response struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatal(err)
		}
		return response.ID
	}
	owner := create("/api/v1/owners", map[string]any{"kind": "workload", "name": "lab-site", "application_id": "lab-site", "environment": "evaluation", "email": "lab@example.test"})
	target := create("/api/v1/connectors/targets", map[string]any{
		"name": "lab/site", "connector": "postfix", "enabled": true,
		"config": map[string]any{"executor": "agent", "required_agent_role": "host", "required_agent_id": seedDestinationHost(t, h.store, h.tenant),
			"postfix_cert_path": "/mail/tls/smtp.crt", "postfix_key_path": "/mail/tls/smtp.key",
			"dovecot_cert_path": "/mail/tls/imap.crt", "dovecot_key_path": "/mail/tls/imap.key",
			"verify_address": "127.0.0.1:1465", "verify_server_name": "mail.endpoint.test"},
	})
	identity := create("/api/v1/identities", map[string]any{"kind": "x509_certificate", "name": "mail.endpoint.test", "owner_id": owner})
	code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/connectors/targets/"+target+"/deploy", admin, "host-deploy-unattested", map[string]any{"identity_id": identity})
	if code != http.StatusConflict || !bytes.Contains(body, []byte("ownership")) {
		t.Fatalf("deploy with an unattested owner: status=%d body=%s; want 409 naming ownership readiness before any host work is queued", code, body)
	}
	if n := outboxRowsForTenant(t, h); n != 0 {
		t.Fatalf("the refused deploy queued %d outbox rows; a refusal must leave nothing for the host or the CA", n)
	}
	code, body = secretsReq(t, h, http.MethodGet, "/api/v1/identities/"+identity, admin, nil)
	if code != http.StatusOK || !bytes.Contains(body, []byte(`"status":"requested"`)) {
		t.Fatalf("identity after the refusal: status=%d body=%s; want still requested", code, body)
	}

	if code, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/owners/"+owner+"/attest", admin, "attest-lab-site", nil); code != http.StatusOK {
		t.Fatalf("attest owner: status=%d body=%s", code, body)
	}
	code, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/connectors/targets/"+target+"/deploy", admin, "host-deploy-attested", map[string]any{"identity_id": identity})
	if code != http.StatusOK {
		t.Fatalf("deploy after attestation: status=%d body=%s", code, body)
	}
	if n := outboxRowsForTenant(t, h); n == 0 {
		t.Fatal("the attested deploy queued no issuance work")
	}
}

func outboxRowsForTenant(t *testing.T, h *servedHarness) int {
	t.Helper()
	var count int
	if err := h.store.SystemPool().QueryRow(t.Context(),
		`SELECT count(*) FROM outbox WHERE tenant_id = $1 AND destination IN ('ca.issue', 'endpoint.renew', 'connector.deploy')`,
		h.tenant).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
