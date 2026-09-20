// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

// TestJOURNEY001WorkloadOwnerSelfServesAttestedOnboarding proves the workload
// owner can configure attester trust, issue and renew an attested SVID, then
// revoke and offboard the trust source without editing process config or the DB.
func TestJOURNEY001WorkloadOwnerSelfServesAttestedOnboarding(t *testing.T) {
	first := servedDynamicK8sTrustFixture(t, "journey-k8s-k1")
	rotated := servedDynamicK8sTrustFixture(t, "journey-k8s-k2")
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AttestedIssuance = AttestedIssuanceConfig{
			Enabled:     true,
			TrustDomain: "served.test",
			DefaultTTL:  10 * time.Minute,
			MaxTTL:      time.Hour,
		}
	})
	token := seedScopedTokenSubject(t, h.store, h.tenant, "workload-owner@example.test",
		"certs:issue", "certs:read", "issuers:read", "issuers:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources",
		token, "journey-001-trust-create", map[string]any{
			"name":     "payments-k8s",
			"method":   "k8s_sat",
			"issuer":   "https://kubernetes.default.svc",
			"audience": "trstctl",
			"jwks":     first.JWKS,
		})
	if status != http.StatusCreated {
		t.Fatalf("create workload attester trust source: status %d body %s", status, body)
	}
	if jsonContainsPrivateMaterial(body) {
		t.Fatalf("trust-source response leaked private material: %s", body)
	}
	var created servedWorkloadTrustSourceResponse
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode trust source: %v body=%s", err, body)
	}
	if created.ID == "" || created.Method != "k8s_sat" || created.RotationVersion != 1 || !created.Enabled {
		t.Fatalf("created trust source lost required fields: %+v", created)
	}
	previewBody := map[string]any{
		"method": "k8s_sat", "payload_base64": base64.StdEncoding.EncodeToString([]byte(first.SAT)),
		"public_key_pem": servedAttestedPublicKeyPEM(t), "ttl_seconds": 600,
	}
	assertTrustPreview := func(wantReady bool) {
		t.Helper()
		status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attested-issuance/preview", token, "", previewBody)
		var preview api.AttestedSVIDPreview
		if status != http.StatusOK || json.Unmarshal(raw, &preview) != nil || preview.Ready != wantReady || !preview.EffectFree {
			t.Fatalf("tenant trust preview ready=%v: status=%d body=%s", wantReady, status, raw)
		}
	}
	assertTrustPreview(true)

	issued := servedAttestedIssue(t, h, token, "journey-001-issue", "k8s_sat", []byte(first.SAT), servedAttestedPublicKeyPEM(t), http.StatusCreated)
	assertServedAttestedSVID(t, h, issued, "spiffe://served.test/_trstctl/v1/tenant/"+h.tenant+"/attested/method/k8s_sat/subject/ns/default/sa/web")

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources/"+created.ID+"/rotate",
		token, "journey-001-trust-rotate", map[string]any{
			"issuer":   "https://kubernetes.default.svc",
			"audience": "trstctl",
			"jwks":     rotated.JWKS,
			"reason":   "cluster service-account signing key rotation",
		})
	if status != http.StatusOK {
		t.Fatalf("rotate workload attester trust source: status %d body %s", status, body)
	}
	var rotation struct {
		TrustSource servedWorkloadTrustSourceResponse `json:"trust_source"`
	}
	if err := json.Unmarshal(body, &rotation); err != nil {
		t.Fatalf("decode rotated trust source: %v body=%s", err, body)
	}
	if rotation.TrustSource.RotationVersion != 2 || rotation.TrustSource.LastRotatedAt == "" {
		t.Fatalf("rotated trust source missing rotation evidence: %+v", rotation.TrustSource)
	}

	renewed := servedAttestedIssue(t, h, token, "journey-001-renew", "k8s_sat", []byte(rotated.SAT), servedAttestedPublicKeyPEM(t), http.StatusCreated)
	assertServedAttestedSVID(t, h, renewed, "spiffe://served.test/_trstctl/v1/tenant/"+h.tenant+"/attested/method/k8s_sat/subject/ns/default/sa/web")
	if renewed.CredentialID == issued.CredentialID {
		t.Fatalf("renewal reused the original SVID credential id: first=%s renewed=%s", issued.CredentialID, renewed.CredentialID)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources/"+created.ID+"/revoke",
		token, "journey-001-trust-revoke", map[string]any{"reason": "workload owner offboarding"})
	if status != http.StatusOK {
		t.Fatalf("revoke workload attester trust source: status %d body %s", status, body)
	}
	assertTrustPreview(false)
	rejected := servedAttestedIssue(t, h, token, "journey-001-after-revoke", "k8s_sat", []byte(rotated.SAT), servedAttestedPublicKeyPEM(t), http.StatusUnprocessableEntity)
	if rejected.CertificatePEM != "" {
		t.Fatalf("revoked trust source still issued a certificate: %+v", rejected)
	}

	status, body = secretsReqKey(t, h, http.MethodDelete, "/api/v1/workloads/attester-trust-sources/"+created.ID,
		token, "journey-001-trust-delete", nil)
	if status != http.StatusNoContent {
		t.Fatalf("delete workload attester trust source: status %d body %s", status, body)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/workloads/attester-trust-sources", token, nil)
	if status != http.StatusOK {
		t.Fatalf("list workload attester trust sources: status %d body %s", status, body)
	}
	var list struct {
		Items []servedWorkloadTrustSourceResponse `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decode trust source list: %v body=%s", err, body)
	}
	if len(list.Items) != 0 {
		t.Fatalf("offboarded trust source still listed: %+v", list.Items)
	}

	for _, eventType := range []string{
		"workload.attester_trust_source.upserted",
		"workload.attester_trust_source.rotated",
		"workload.attester_trust_source.revoked",
		"workload.attester_trust_source.deleted",
		"certificate.recorded",
		"attestation.verified",
		"attestation.bound",
	} {
		if !h.hasEvent(t, eventType) {
			t.Fatalf("served workload journey did not emit %s", eventType)
		}
	}
}

func TestWorkloadAttesterTrustSourceDuplicateNameFailsBeforeEventAppend(t *testing.T) {
	fixture := servedDynamicK8sTrustFixture(t, "duplicate-name-k1")
	h := newServedHarness(t, config.Protocols{}, func(*Deps) {})
	token := seedScopedTokenSubject(t, h.store, h.tenant, "trust-admin@example.test", "certs:issue", "certs:read")
	request := map[string]any{
		"name": "Payments K8s", "method": "k8s_sat",
		"issuer": "https://kubernetes.default.svc", "audience": "trstctl", "jwks": fixture.JWKS,
	}
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources",
		token, "duplicate-name-first", request)
	if status != http.StatusCreated {
		t.Fatalf("create first trust source: status=%d body=%s", status, body)
	}
	headBefore, err := h.log.LastSequence(t.Context())
	if err != nil {
		t.Fatalf("read event head before duplicate: %v", err)
	}
	request["name"] = "  payments k8s  "
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources",
		token, "duplicate-name-second", request)
	if status != http.StatusConflict || !strings.Contains(strings.ToLower(string(body)), "already exists") {
		t.Fatalf("duplicate trust-source name = status %d body %s, want safe 409", status, body)
	}
	headAfter, err := h.log.LastSequence(t.Context())
	if err != nil || headAfter != headBefore {
		t.Fatalf("duplicate trust-source command appended an invalid event: before=%d after=%d err=%v", headBefore, headAfter, err)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/workloads/attester-trust-sources", token, nil)
	if status != http.StatusOK {
		t.Fatalf("list after duplicate rejection: status=%d body=%s", status, body)
	}
	var list struct {
		Items []servedWorkloadTrustSourceResponse `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil || len(list.Items) != 1 {
		t.Fatalf("duplicate rejection did not preserve exactly one source: items=%+v err=%v", list.Items, err)
	}
}

type servedWorkloadTrustSourceResponse struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Method          string         `json:"method"`
	Enabled         bool           `json:"enabled"`
	RotationVersion int            `json:"rotation_version"`
	LastRotatedAt   string         `json:"last_rotated_at"`
	JWKS            map[string]any `json:"jwks"`
}

type servedDynamicK8sTrust struct {
	JWKS       map[string]any
	SAT        string
	ExpiredSAT string
}

func servedDynamicK8sTrustFixture(t *testing.T, kid string) servedDynamicK8sTrust {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("k8s dynamic trust signer: %v", err)
	}
	t.Cleanup(signer.Destroy)
	jwk, err := crypto.PublicJWK(signer.Public(), kid)
	if err != nil {
		t.Fatalf("k8s dynamic trust jwk: %v", err)
	}
	doc, err := json.Marshal(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	if err != nil {
		t.Fatalf("marshal dynamic trust jwks: %v", err)
	}
	var jwks map[string]any
	if err := json.Unmarshal(doc, &jwks); err != nil {
		t.Fatalf("decode dynamic trust jwks: %v", err)
	}
	return servedDynamicK8sTrust{
		JWKS: jwks, SAT: servedK8sSAT(t, signer, kid),
		ExpiredSAT: servedK8sSATWithExpiry(t, signer, kid, time.Now().Add(-time.Minute)),
	}
}

func jsonContainsPrivateMaterial(body []byte) bool {
	return containsAny(string(body), "PRIVATE KEY", "private_key", "secret", base64.StdEncoding.EncodeToString([]byte("private")))
}

func containsAny(s string, needles ...string) bool {
	for _, needle := range needles {
		if needle != "" && strings.Contains(s, needle) {
			return true
		}
	}
	return false
}
