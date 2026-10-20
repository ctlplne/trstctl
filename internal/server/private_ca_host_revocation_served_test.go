// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/orchestrator"
)

// A host-executed identity issued from a private CA hierarchy authority is
// revoked through the same lifecycle command as a platform-issued one. The
// publisher must resolve that leaf's issuing authority from its retained
// issuance evidence and publish through that CA; a leaf it cannot attribute
// would otherwise leave the revocation command retrying forever while the
// operator has already been told the identity is revoked.
func TestServedPrivateCAHostLeafRevocationPublishes(t *testing.T) {
	ctx := t.Context()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, agentJobKindEndpointRenew)
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "private-ca-operator@example.test",
		"issuers:write", "issuers:read", "certs:issue", "certs:read", "certs:revoke",
		"identities:write", "identities:read", "connectors:write", "connectors:read", "owners:write")
	first := seedScopedTokenSubject(t, h.store, h.tenant, "private-ca-custodian-one@example.test", "issuers:write", "issuers:read")
	second := seedScopedTokenSubject(t, h.store, h.tenant, "private-ca-custodian-two@example.test", "issuers:write", "issuers:read")
	rootSpec := map[string]any{
		"common_name": "private host root", "max_path_len": 1,
		"ttl_seconds":           int64((365 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"revocation.test"},
		"extended_key_usages":   []string{"serverAuth"}, "signature_algorithm": "ecdsa-p256",
	}
	rootCeremony := createCACeremony(t, h.servedHarness, operator, "create_root", "", rootSpec, 2, "private-host-root-ceremony")
	approveCACeremony(t, h.servedHarness, first, rootCeremony.ID, 1, "private-host-root-first")
	approveCACeremony(t, h.servedHarness, second, rootCeremony.ID, 2, "private-host-root-second")
	root := createRootCA(t, h.servedHarness, operator, rootCeremony.ID, rootSpec, "private-host-root-create")
	issuerSpec := map[string]any{
		"common_name": "private host issuer", "ttl_seconds": int64((180 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"revocation.test"},
		"extended_key_usages":   []string{"serverAuth"}, "signature_algorithm": "ecdsa-p256",
	}
	issuerCeremony := createCACeremony(t, h.servedHarness, operator, "create_intermediate", root.ID, issuerSpec, 2, "private-host-issuer-ceremony")
	approveCACeremony(t, h.servedHarness, first, issuerCeremony.ID, 1, "private-host-issuer-first")
	approveCACeremony(t, h.servedHarness, second, issuerCeremony.ID, 2, "private-host-issuer-second")
	issuer := createIntermediateCA(t, h.servedHarness, operator, issuerCeremony.ID, root.ID, issuerSpec, "private-host-issuer-create")

	post := func(path string, input any, expected int) map[string]json.RawMessage {
		t.Helper()
		code, body := secretsReq(t, h.servedHarness, http.MethodPost, path, operator, input)
		if code != expected {
			t.Fatalf("POST %s: status=%d body=%s", path, code, body)
		}
		var result map[string]json.RawMessage
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	str := func(raw json.RawMessage) string {
		t.Helper()
		var result string
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	owner := str(post("/api/v1/owners", map[string]any{"kind": "workload", "name": "private CA host revocation"}, http.StatusCreated)["id"])
	target := str(post("/api/v1/connectors/targets", map[string]any{
		"name": "private-mail", "connector": "postfix", "enabled": true,
		"config": map[string]any{"executor": "agent", "required_agent_role": "host", "required_agent_id": registeredRoleAgentID(t, h),
			"postfix_cert_path": "/mail/tls/smtp.crt", "postfix_key_path": "/mail/tls/smtp.key",
			"dovecot_cert_path": "/mail/tls/imap.crt", "dovecot_key_path": "/mail/tls/imap.key",
			"verify_address": "127.0.0.1:1465", "verify_server_name": "mail.revocation.test"},
	}, http.StatusCreated)["id"])
	request := map[string]any{"owner_id": owner, "identity_name": "mail.revocation.test", "target_id": target,
		"issuer": map[string]any{"source": "private", "id": issuer.ID}, "reason": "private CA host revocation"}
	preview := post("/api/v1/lifecycle/endpoint-bindings/preview", request, http.StatusOK)
	request["preview_fingerprint"] = str(preview["request_fingerprint"])
	binding := post("/api/v1/lifecycle/endpoint-bindings", request, http.StatusCreated)
	var identity struct{ ID string }
	if err := json.Unmarshal(binding["identity"], &identity); err != nil {
		t.Fatal(err)
	}
	if dispatched, err := h.srv.DispatchIssuanceOnce(ctx); err != nil || !dispatched {
		t.Fatalf("dispatch authorized first issuance: dispatched=%v err=%v", dispatched, err)
	}

	job := claimOneRenewal(t, ctx, h)
	key, err := crypto.GenerateHostSubjectKey("mail.revocation.test", []string{"mail.revocation.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	issued, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{JobID: job.JobID, Attempt: job.Attempt, CSRDER: key.CSRDER})
	if err != nil {
		t.Fatalf("sign the host CSR with the private CA: %v", err)
	}
	f := hostRotationResultFixture{h: h, job: job, fingerprint: issued.Fingerprint}
	if response, err := h.client.ReportJobResult(ctx, f.report(t, transport.JobOutcomeVerified)); err != nil || !response.Accepted {
		t.Fatalf("verified host report: %+v %v", response, err)
	}
	if current, err := h.store.GetIdentity(ctx, h.tenant, identity.ID); err != nil || current.Status != "deployed" {
		t.Fatalf("identity after verified host issuance: status=%s err=%v", current.Status, err)
	}
	leaf, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, issued.Fingerprint)
	if err != nil || leaf.ID == "" {
		t.Fatalf("served leaf is not in the inventory: %+v %v", leaf, err)
	}

	servedHostLifecycleTransition(t, h, operator, identity.ID, "revoked", "private-ca-revocation", http.StatusOK)
	var rowStatus, lastError string
	for attempt := 0; attempt < 5; attempt++ {
		if _, err := h.srv.outbox.DispatchOneScoped(ctx, h.srv.obHandler,
			orchestrator.DestinationScope{IncludePrefixes: []string{"revocation.publish"}}); err != nil {
			t.Fatalf("dispatch revocation publish: %v", err)
		}
		if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT status, coalesce(last_error, '') FROM outbox
				 WHERE tenant_id = $1 AND destination = 'revocation.publish' ORDER BY id DESC LIMIT 1`, h.tenant).Scan(&rowStatus, &lastError)
		}); err != nil {
			t.Fatal(err)
		}
		if rowStatus == "delivered" {
			break
		}
	}
	if rowStatus != "delivered" {
		t.Fatalf("revocation.publish for a private CA host leaf = %s/%q; want delivered through the issuing hierarchy authority", rowStatus, lastError)
	}
	revoked, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, issued.Fingerprint)
	if err != nil || revoked.Status != "revoked" {
		t.Fatalf("served leaf after revocation: status=%s err=%v", revoked.Status, err)
	}
	issuedCert, found, err := h.store.LookupIssuedCert(ctx, h.tenant, issuer.ID, leaf.Serial)
	if err != nil || !found || issuedCert.RevokedAt == nil {
		t.Fatalf("the issuing authority's own issued-certificate record does not carry the revocation: found=%v err=%v record=%+v", found, err, issuedCert)
	}
}
