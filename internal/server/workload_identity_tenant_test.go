// SPDX-License-Identifier: MPL-2.0

// SPIFFE-TENANT-001: different tenants must not obtain the same identity under
// a shared CA, even when their independently trusted proofs name the same workload.
package server

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

func TestServedEphemeralIdentitiesAndApprovalsAreTenantIsolated(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EphemeralIssuance = EphemeralIssuanceConfig{Enabled: true, TrustDomain: "served.test", DefaultTTL: time.Minute, MaxTTL: 2 * time.Minute, ApprovalTTL: time.Minute, RequiredApprovals: 1}
	})
	const tenantB = "22222222-2222-4222-8222-222222222222"
	registerServedTenantID(t, h, tenantB, "Independent approved identity tenant")
	certs := []stockIdentityCertificate{}
	expectedIDs := []string{}
	for _, tenant := range []string{h.tenant, tenantB} {
		fixture := servedDynamicK8sTrustFixture(t, "independent-ephemeral-proof")
		requester := seedScopedTokenSubject(t, h.store, tenant, "tenant-requester", "certs:request", "certs:read")
		approver := seedScopedTokenSubject(t, h.store, tenant, "tenant-approver", "certs:issue", "certs:read")
		otherTenant := tenantB
		if tenant == tenantB {
			otherTenant = h.tenant
		}
		otherApprover := seedScopedTokenSubject(t, h.store, otherTenant, "other-tenant-approver", "certs:issue", "certs:read")
		status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources", approver, "approved-identity-trust", map[string]any{
			"name": "independent-k8s", "method": "k8s_sat", "issuer": "https://kubernetes.default.svc", "audience": "trstctl", "jwks": fixture.JWKS,
		})
		if status != http.StatusCreated {
			t.Fatalf("tenant trust creation HTTP %d", status)
		}
		body := map[string]any{"request_id": "same-request-name", "method": "k8s_sat", "payload_base64": base64.StdEncoding.EncodeToString([]byte(fixture.SAT)), "public_key_pem": servedAttestedPublicKeyPEM(t), "ttl_seconds": 60}
		pending := servedEphemeralIssue(t, h, requester, "same-approval-request-key", body, http.StatusAccepted)
		if pending.CertificatePEM != "" || pending.SPIFFEID != "" {
			t.Fatal("pending approval emitted a credential or claimed a signed workload identity")
		}
		status, denied := secretsReqKey(t, h, http.MethodPost, "/api/v1/ephemeral/"+pending.ApprovalRequestID+"/approvals", otherApprover, "cross-tenant-approval", map[string]any{
			"action": "issue", "request_id": pending.ApprovalRequestID, "intent_digest": pending.IntentDigest,
		})
		var problem struct {
			Status int    `json:"status"`
			Code   string `json:"code"`
		}
		if status != http.StatusNotFound || json.Unmarshal(denied, &problem) != nil || problem.Status != http.StatusNotFound || problem.Code != "problem.resource.not_found" {
			t.Fatalf("cross-tenant approval did not return a closed not-found problem: HTTP %d", status)
		}
		servedEphemeralApprove(t, h, approver, "same-approval-decision-key", pending.ApprovalRequestID, pending.IntentDigest, http.StatusOK)
		issued := servedEphemeralIssue(t, h, requester, "same-approved-issue-key", body, http.StatusCreated)
		replayed := servedEphemeralIssue(t, h, requester, "same-approved-issue-key", body, http.StatusCreated)
		if issued.CertificatePEM != replayed.CertificatePEM || issued.CertificateID != replayed.CertificateID || issued.Subject != "ns/default/sa/web" {
			t.Fatal("approved replay or original subject changed")
		}
		block, rest := pem.Decode([]byte(issued.CertificatePEM))
		if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
			t.Fatal("expected one public approved leaf")
		}
		certs = append(certs, stockIdentityCertificate{DER: block.Bytes, CA: h.srv.ephemeralIssuer.caCertDER, TrustDomain: "served.test"})
		expectedIDs = append(expectedIDs, "spiffe://served.test/_trstctl/v1/tenant/"+tenant+"/ephemeral/method/k8s_sat/subject/ns/default/sa/web")
		assertSignedWorkloadIDHandoff(t, issued.CertificatePEM, issued.SPIFFEID, expectedIDs[len(expectedIDs)-1])
		if replayed.SPIFFEID != issued.SPIFFEID {
			t.Fatal("approved replay changed the signed workload identity handoff")
		}
	}
	results := runStockIdentityChecks(t, nil, certs)
	if len(results.Certificates) != len(expectedIDs) {
		t.Fatal("stock verifier returned an incomplete result")
	}
	for i, result := range results.Certificates {
		if !result.Accepted || result.ID != expectedIDs[i] {
			t.Fatalf("approved tenant credential %d failed exact stock verification", i)
		}
	}
	if results.Certificates[0].ID == results.Certificates[1].ID {
		t.Fatal("approved credentials from different tenants share an identity")
	}
}

func TestServedWorkloadIdentitiesAreTenantIsolated(t *testing.T) {
	h, tokenA, bodyA := servedPublicBrokerRevocationFixture(t, func(d *Deps) {
		d.AttestedIssuance = AttestedIssuanceConfig{Enabled: true, TrustDomain: "served.test"}
	})
	const tenantB = "22222222-2222-2222-2222-222222222222"
	registerServedTenantID(t, h, tenantB, "Independent identity tenant")
	tokenB := seedScopedToken(t, h.store, tenantB, "certs:issue", "certs:read", "identities:write")
	keyB, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer keyB.Destroy()
	jwkB, err := crypto.PublicJWK(keyB.Public(), "served-clock-key")
	if err != nil {
		t.Fatal(err)
	}
	status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources", tokenB, "tenant-b-own-proof-trust", map[string]any{
		"name": "tenant-b-own-proof-trust", "method": "k8s_sat", "issuer": "https://kubernetes.default.svc", "audience": "trstctl",
		"jwks": crypto.JWKS{Keys: []crypto.JWK{jwkB}},
	})
	if status != http.StatusCreated {
		t.Fatalf("tenant B independent trust: HTTP %d", status)
	}
	bodyB := servedClockProofBody(t, keyB, servedAttestedPublicKeyPEM(t), func(claims map[string]any) {
		// Tenant B can choose fields in its own signed proof. Those fields must
		// never replace the authenticated tenant used for the certificate name.
		claims["tenant_id"] = h.tenant
		claims["spiffe_id"] = "spiffe://served.test/_trstctl/v1/tenant/" + h.tenant + "/attested/method/k8s_sat/subject/ns/qa/sa/clock-reader"
	})
	bodyB["agent_id"], bodyB["scopes"] = "agent-7", []string{"tool:inventory.read"}
	certs := []stockIdentityCertificate{}
	expectedIDs := []string{}
	for _, surface := range []string{"broker", "attested"} {
		route := "/api/v1/broker/agent-identities"
		if surface == "attested" {
			route = "/api/v1/workloads/attested-issuance"
			delete(bodyA, "agent_id")
			delete(bodyA, "scopes")
			delete(bodyB, "agent_id")
			delete(bodyB, "scopes")
		}
		certificateA := ""
		status, _ := secretsReqKey(t, h, http.MethodPost, route, tokenB, "tenant-b-cannot-borrow-a-proof-"+surface, bodyA)
		if status != http.StatusForbidden {
			t.Fatalf("%s accepted the other tenant's independent proof key: HTTP %d", surface, status)
		}
		for i, request := range []struct {
			token string
			body  map[string]any
		}{{tokenA, bodyA}, {tokenB, bodyB}} {
			status, raw := secretsReqKey(t, h, http.MethodPost, route, request.token, "tenant-isolation-"+surface, request.body)
			var response struct {
				CertificatePEM string `json:"certificate_pem"`
				CertificateID  string `json:"certificate_id"`
				SPIFFEID       string `json:"spiffe_id"`
			}
			if status != http.StatusCreated || json.Unmarshal(raw, &response) != nil {
				t.Fatalf("%s tenant index %d issuance: HTTP %d", surface, i, status)
			}
			block, rest := pem.Decode([]byte(response.CertificatePEM))
			if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
				t.Fatal("expected one public leaf")
			}
			certs = append(certs, stockIdentityCertificate{DER: block.Bytes, CA: h.srv.agentBroker.caCertDER, TrustDomain: "served.test"})
			tenant := h.tenant
			if i == 1 {
				tenant = tenantB
			}
			kind := surface
			if surface == "broker" {
				kind += "/agent/agent-7"
			}
			expectedIDs = append(expectedIDs, "spiffe://served.test/_trstctl/v1/tenant/"+tenant+"/"+kind+"/method/k8s_sat/subject/ns/qa/sa/clock-reader")
			assertSignedWorkloadIDHandoff(t, response.CertificatePEM, response.SPIFFEID, expectedIDs[len(expectedIDs)-1])
			replayStatus, replayRaw := secretsReqKey(t, h, http.MethodPost, route, request.token, "tenant-isolation-"+surface, request.body)
			var replay struct {
				SPIFFEID       string `json:"spiffe_id"`
				CertificatePEM string `json:"certificate_pem"`
			}
			if replayStatus != http.StatusCreated || json.Unmarshal(replayRaw, &replay) != nil || replay.SPIFFEID != response.SPIFFEID || replay.CertificatePEM != response.CertificatePEM {
				t.Fatal("exact issuance replay changed the signed identity or certificate")
			}
			if i == 0 {
				certificateA = response.CertificateID
			}
		}
		if surface == "broker" {
			status, _ := secretsReq(t, h, http.MethodGet, "/api/v1/broker/agent-identities/"+certificateA, tokenB, nil)
			if status != http.StatusNotFound {
				t.Fatalf("storage isolation control: HTTP %d", status)
			}
			t.Log("tenant B cannot read tenant A broker record: HTTP 404")
		}
	}
	results := runStockIdentityChecks(t, nil, certs)
	if len(results.Certificates) != len(expectedIDs) {
		t.Fatal("stock verifier returned an incomplete result")
	}
	for i, result := range results.Certificates {
		if !result.Accepted {
			t.Fatalf("stock verifier rejected signed diagnostic certificate %d: %s", i, result.Error)
		}
		if result.ID != expectedIDs[i] {
			t.Fatalf("credential %d did not bind the authenticated tenant and exact authority context", i)
		}
	}
	for i, surface := range []string{"broker", "attested"} {
		a, b := results.Certificates[2*i].ID, results.Certificates[2*i+1].ID
		if a == b {
			t.Errorf("TENANT IDENTITY COLLISION: %s credentials from independent tenant-scoped proof keys both verify under the same CA as %s", surface, a)
		}
	}
	t.Logf("public issuing CA DER SHA256: %s", crypto.SHA256Hex(h.srv.agentBroker.caCertDER))
}

func assertSignedWorkloadIDHandoff(t *testing.T, certificatePEM, advertised, expected string) {
	t.Helper()
	block, rest := pem.Decode([]byte(certificatePEM))
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatal("signed identity handoff requires the actual single public certificate")
	}
	actual, err := crypto.SPIFFEIDFromCert(block.Bytes)
	if err != nil || actual != expected {
		t.Fatalf("actual signed certificate has the wrong workload identity: %v", err)
	}
	if advertised == "" || advertised != actual {
		t.Fatal("API spiffe_id is missing or disagrees with the actual signed certificate; the friendly subject is not the full identity")
	}
}
