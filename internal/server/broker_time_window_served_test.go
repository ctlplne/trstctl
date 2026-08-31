// SPDX-License-Identifier: MPL-2.0

package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

func TestServedBrokerAndSVIDRejectUnusableJWTTimeWindowsBeforeSigning(t *testing.T) {
	authority, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Destroy()
	jwk, err := crypto.PublicJWK(authority.Public(), "served-clock-key")
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AgentBroker = AgentBrokerConfig{Enabled: true, TrustDomain: "served.test", PolicyModule: servedBrokerAllowPolicy}
		d.AttestedIssuance = AttestedIssuanceConfig{Enabled: true, TrustDomain: "served.test"}
	})
	owner := seedScopedToken(t, h.store, h.tenant, "certs:issue", "certs:read")
	status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources", owner, "served-clock-trust", map[string]any{
		"name": "served-clock-trust", "method": "k8s_sat", "issuer": "https://kubernetes.default.svc", "audience": "trstctl",
		"jwks": crypto.JWKS{Keys: []crypto.JWK{jwk}},
	})
	if status != http.StatusCreated {
		t.Fatalf("register tenant public trust: HTTP %d", status)
	}
	brokerSigner := &countingEphemeralDigestSigner{DigestSigner: h.srv.agentBroker.caSigner}
	svidSigner := &countingEphemeralDigestSigner{DigestSigner: h.srv.attestedIssuance.caSigner}
	h.srv.agentBroker.caSigner, h.srv.attestedIssuance.caSigner = brokerSigner, svidSigner
	publicKey := servedAttestedPublicKeyPEM(t)
	const firstPage = "00000000-0000-0000-0000-000000000000"
	baseline, err := h.store.ListCertificatesPage(t.Context(), h.tenant, firstPage, nil, 100, nil)
	if err != nil || len(baseline) != 0 {
		t.Fatalf("expected empty certificate baseline: count=%d error=%v", len(baseline), err)
	}
	cases := []struct {
		name string
		edit func(map[string]any)
	}{
		{"future-start", func(c map[string]any) { c["nbf"] = time.Now().Add(time.Hour).Unix() }},
		{"future-issued-at", func(c map[string]any) { c["iat"] = time.Now().Add(time.Hour).Unix() }},
		{"missing-expiry", func(c map[string]any) { delete(c, "exp") }},
		{"null-expiry", func(c map[string]any) { c["exp"] = nil }},
		{"malformed-start", func(c map[string]any) { c["nbf"] = "later" }},
		{"expired", func(c map[string]any) { c["exp"] = time.Now().Unix() }},
	}
	for i, tc := range cases {
		for _, surface := range []string{"broker", "svid"} {
			t.Run(surface+"/"+tc.name, func(t *testing.T) {
				body := servedClockProofBody(t, authority, publicKey, tc.edit)
				route := "/api/v1/workloads/attested-issuance"
				if surface == "broker" {
					route = "/api/v1/broker/agent-identities"
					body["agent_id"], body["scopes"] = "agent-7", []string{"tool:inventory.read"}
				}
				status, raw := secretsReqKey(t, h, http.MethodPost, route+"/preview", owner, "", body)
				var preview struct {
					Ready      bool `json:"ready"`
					EffectFree bool `json:"effect_free"`
				}
				if status != http.StatusOK || json.Unmarshal(raw, &preview) != nil || !preview.Ready || !preview.EffectFree {
					t.Fatal("configured effect-free preview failed")
				}
				status, _ = secretsReqKey(t, h, http.MethodPost, route, owner, fmt.Sprintf("served-clock-%s-%d", surface, i), body)
				if status != http.StatusForbidden {
					t.Fatalf("unusable proof after ready preview: HTTP %d, want 403", status)
				}
				certs, err := h.store.ListCertificatesPage(t.Context(), h.tenant, firstPage, nil, 100, nil)
				if err != nil || len(certs) != 0 || brokerSigner.calls.Load() != 0 || svidSigner.calls.Load() != 0 {
					t.Fatalf("refused proof effects: query_error=%v certificate_count=%d broker_signs=%d svid_signs=%d", err, len(certs), brokerSigner.calls.Load(), svidSigner.calls.Load())
				}
			})
		}
	}
	for _, surface := range []string{"broker", "svid"} {
		body := servedClockProofBody(t, authority, publicKey, nil)
		route := "/api/v1/workloads/attested-issuance"
		if surface == "broker" {
			route = "/api/v1/broker/agent-identities"
			body["agent_id"], body["scopes"] = "agent-7", []string{"tool:inventory.read"}
		}
		status, _ := secretsReqKey(t, h, http.MethodPost, route, owner, "served-clock-valid-"+surface, body)
		if status != http.StatusCreated {
			t.Fatalf("valid %s proof stopped working: HTTP %d", surface, status)
		}
	}
	if brokerSigner.calls.Load() != 1 || svidSigner.calls.Load() != 1 {
		t.Fatal("positive controls must each sign exactly once")
	}
}

func servedClockProofBody(t *testing.T, signer crypto.DigestSigner, publicKey string, edit func(map[string]any)) map[string]any {
	t.Helper()
	now := time.Now().Unix()
	claims := map[string]any{
		"iss": "https://kubernetes.default.svc", "aud": []string{"trstctl"}, "sub": "system:serviceaccount:qa:clock-reader",
		"exp": now + 7200, "nbf": now - 60, "iat": now - 60,
		"kubernetes.io": map[string]any{"namespace": "qa", "serviceaccount": map[string]any{"name": "clock-reader"}},
	}
	if edit != nil {
		edit(claims)
	}
	proof, err := crypto.SignJWT(signer, "served-clock-key", claims)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"method": "k8s_sat", "payload_base64": base64.StdEncoding.EncodeToString([]byte(proof)), "public_key_pem": publicKey, "ttl_seconds": 120}
}
