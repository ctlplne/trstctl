// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/orchestrator"
)

// Real API enrollment, PostgreSQL/NATS handoff and authenticated host CSR/report
// RPCs must compose across renewals. Separate listener tests prove deployment;
// these signed fixture reports only exercise the control-plane receiver.
func TestServedHostRenewalsRetainShortProfile(t *testing.T) {
	testServedHostRenewalProfile(t, false)
}

func TestServedHostRenewalsKeepPolicyWhenDefaultChanges(t *testing.T) {
	testServedHostRenewalProfile(t, true)
}

func testServedHostRenewalProfile(t *testing.T, changeDefault bool) {
	t.Helper()
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, []string{agentJobKindEndpointRenew}, func(d *Deps) {
		d.DefaultProfile = "mail-short-life"
	})
	// The enrolled role agent is bound to the fixture's existing registration.
	// Reuse it; a second registration would invalidate that authority.
	token := seedScopedToken(t, h.store, h.tenant, "owners:write", "connectors:write", "certs:issue", "profiles:write", "identities:write")
	post := func(path string, input any, expected int) map[string]json.RawMessage {
		t.Helper()
		code, body := secretsReq(t, h.servedHarness, http.MethodPost, path, token, input)
		if code != expected {
			t.Fatalf("POST %s: HTTP %d: %s", path, code, body)
		}
		var result map[string]json.RawMessage
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	str := func(raw json.RawMessage) string {
		t.Helper()
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	profileID := str(post("/api/v1/profiles", map[string]any{"name": "mail-short-life", "spec": map[string]any{
		"max_validity": "12m", "allowed_protocols": []string{"api"}, "allowed_dns_suffixes": []string{"renewal.test"},
	}}, http.StatusCreated)["id"])
	if changeDefault {
		post("/api/v1/profiles", map[string]any{"name": "java-short-life", "spec": map[string]any{
			"max_validity": "12m", "allowed_protocols": []string{"api"}, "allowed_dns_suffixes": []string{"java.other.test"},
		}}, http.StatusCreated)
	}
	owner := str(post("/api/v1/owners", map[string]any{"kind": "workload", "name": "Mail renewal QA"}, http.StatusCreated)["id"])
	target := str(post("/api/v1/connectors/targets", map[string]any{
		"name": "renewal-mail", "connector": "postfix", "enabled": true,
		"config": map[string]any{"executor": "agent", "required_agent_role": "host", "required_agent_id": registeredRoleAgentID(t, h),
			"postfix_cert_path": "/mail/smtp.crt", "postfix_key_path": "/mail/smtp.key",
			"dovecot_cert_path": "/mail/imap.crt", "dovecot_key_path": "/mail/imap.key",
			"verify_address": "127.0.0.1:1465", "verify_server_name": "mail.renewal.test"},
	}, http.StatusCreated)["id"])
	request := map[string]any{"owner_id": owner, "identity_name": "mail.renewal.test", "target_id": target,
		"issuer": map[string]any{"source": "platform", "id": "trstctl-issuing-ca"}, "reason": "prove repeated host renewal"}
	request["preview_fingerprint"] = str(post("/api/v1/lifecycle/endpoint-bindings/preview", request, http.StatusOK)["request_fingerprint"])
	enrolled := post("/api/v1/lifecycle/endpoint-bindings", request, http.StatusCreated)
	var identity struct{ ID string }
	if err := json.Unmarshal(enrolled["identity"], &identity); err != nil {
		t.Fatal(err)
	}
	previous := ""
	wantVersion, wantTTL := 1, 12*time.Minute
	for generation := 0; generation < 3; generation++ {
		if generation == 1 && changeDefault {
			// Model the runtime default changing after the first installation.
			// Public renew transitions carry no new issuance binding: the
			// dispatcher must resolve this identity's policy, not this default.
			h.srv.obHandler.(*issuanceDispatcher).defaultProfile = "java-short-life"
		}
		if generation == 2 {
			wantVersion, wantTTL = 2, 10*time.Minute
		}
		if generation > 0 {
			code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/identities/"+identity.ID+"/transitions", token,
				fmt.Sprintf("mail-renewal-%d", generation), map[string]any{"to": "renewing", "reason": "prove short-profile renewal"})
			if code != http.StatusOK {
				t.Fatalf("renew: HTTP %d: %s", code, body)
			}
		}
		kind := "ca.issue"
		if generation > 0 {
			kind = "ca.renew"
		}
		if _, err := h.srv.outbox.DispatchOneScoped(t.Context(), h.srv.obHandler, orchestrator.DestinationScope{IncludePrefixes: []string{kind}}); err != nil {
			t.Fatalf("generation %d dispatch: %v", generation, err)
		}
		claimed, err := h.client.ClaimJobs(t.Context(), &transport.ClaimJobsRequest{Kinds: []string{agentJobKindEndpointRenew}, Limit: 1})
		if err != nil || len(claimed.Jobs) != 1 {
			var queue []byte
			readErr := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
				return tx.QueryRow(t.Context(), `SELECT jsonb_agg(jsonb_build_object('kind', destination, 'status', status, 'error', last_error)) FROM outbox WHERE tenant_id = $1`, h.tenant).Scan(&queue)
			})
			t.Fatalf("generation %d claim: %v; queue=%s read=%v", generation, err, queue, readErr)
		}
		job := claimed.Jobs[0]
		var intent RelayDeployIntent
		if err := json.Unmarshal(job.Payload, &intent); err != nil {
			t.Fatal(err)
		}
		if intent.Issuance == nil || intent.Issuance.ProfileID != profileID || intent.Issuance.ProfileVersion != wantVersion || intent.Issuance.EffectiveTTLSeconds != int64(wantTTL/time.Second) {
			t.Fatalf("generation %d lost profile authority: %+v", generation, intent.Issuance)
		}
		if generation == 1 {
			// Editing policy after handoff must not reinterpret this queued job.
			// The following renewal must then resolve the new active revision.
			profileID = str(post("/api/v1/profiles", map[string]any{"name": "mail-short-life", "spec": map[string]any{
				"max_validity": "10m", "allowed_protocols": []string{"api"}, "allowed_dns_suffixes": []string{"renewal.test"},
			}}, http.StatusCreated)["id"])
		}
		key, err := crypto.GenerateHostSubjectKey("mail.renewal.test", []string{"mail.renewal.test"})
		if err != nil {
			t.Fatal(err)
		}
		signed, err := h.client.SignJobCSR(t.Context(), &transport.SignJobCSRRequest{JobID: job.JobID, Attempt: job.Attempt, CSRDER: key.CSRDER})
		key.Destroy()
		if err != nil {
			t.Fatalf("generation %d signing: %v", generation, err)
		}
		cert, err := h.store.GetCertificateByFingerprint(t.Context(), h.tenant, signed.Fingerprint)
		if err != nil || cert.NotBefore == nil || cert.NotAfter == nil || cert.NotAfter.Sub(*cert.NotBefore) != wantTTL || cert.KeyOrigin != "host_agent" {
			t.Fatalf("generation %d certificate validity: %+v %v", generation, cert, err)
		}
		if previous != "" && (cert.ReplacesID == nil || *cert.ReplacesID != previous) {
			t.Fatalf("generation %d lost predecessor %s", generation, previous)
		}
		f := &hostRotationResultFixture{h: h, job: job, fingerprint: signed.Fingerprint}
		if result, err := h.client.ReportJobResult(t.Context(), f.report(t, transport.JobOutcomeVerified)); err != nil || !result.Accepted {
			t.Fatalf("generation %d report: %+v %v", generation, result, err)
		}
		current, err := h.store.GetIdentity(t.Context(), h.tenant, identity.ID)
		if err != nil || current.Status != "deployed" {
			t.Fatalf("generation %d state: %s %v", generation, current.Status, err)
		}
		previous = cert.ID
	}
}
