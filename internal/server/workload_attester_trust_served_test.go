package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

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

	issued := servedAttestedIssue(t, h, token, "journey-001-issue", "k8s_sat", []byte(first.SAT), servedAttestedPublicKeyPEM(t), http.StatusCreated)
	assertServedAttestedSVID(t, h, issued, "spiffe://served.test/ns/default/sa/web")

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
	assertServedAttestedSVID(t, h, renewed, "spiffe://served.test/ns/default/sa/web")
	if renewed.CredentialID == issued.CredentialID {
		t.Fatalf("renewal reused the original SVID credential id: first=%s renewed=%s", issued.CredentialID, renewed.CredentialID)
	}

	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources/"+created.ID+"/revoke",
		token, "journey-001-trust-revoke", map[string]any{"reason": "workload owner offboarding"})
	if status != http.StatusOK {
		t.Fatalf("revoke workload attester trust source: status %d body %s", status, body)
	}
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

type servedWorkloadTrustSourceResponse struct {
	ID              string         `json:"id"`
	Method          string         `json:"method"`
	Enabled         bool           `json:"enabled"`
	RotationVersion int            `json:"rotation_version"`
	LastRotatedAt   string         `json:"last_rotated_at"`
	JWKS            map[string]any `json:"jwks"`
}

type servedDynamicK8sTrust struct {
	JWKS map[string]any
	SAT  string
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
	return servedDynamicK8sTrust{JWKS: jwks, SAT: servedK8sSAT(t, signer, kid)}
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
