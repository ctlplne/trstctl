// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

func TestCR193AttestedPodNameCannotBecomeSSHLogin(t *testing.T) {
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	jwk, err := crypto.PublicJWK(signer.Public(), "cr193-k1")
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	var publicJWKS map[string]any
	if err := json.Unmarshal(jwks, &publicJWKS); err != nil {
		t.Fatal(err)
	}
	proof, err := crypto.SignJWT(signer, "cr193-k1", map[string]any{
		"iss": "https://kubernetes.default.svc", "aud": []string{"trstctl"},
		"exp": time.Now().Add(time.Hour).Unix(),
		"sub": "system:serviceaccount:dev:builder",
		"kubernetes.io": map[string]any{
			"namespace":      "dev",
			"serviceaccount": map[string]any{"name": "builder", "uid": "uid-1"},
			"pod":            map[string]any{"name": "root", "uid": "uid-2"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	protocols := config.Protocols{SSH: config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}}
	protocols.SSHUserPrincipals = []string{"deploy"}
	h := newOperatingServedHarness(t, protocols, func(d *Deps) {
		d.AttestedIssuance = AttestedIssuanceConfig{
			Enabled: true, TrustDomain: "served.test", DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour,
		}
	})
	issuerAdmin := seedScopedToken(t, h.store, h.tenant, "issuers:write")
	issuer := seedScopedToken(t, h.store, h.tenant, "certs:issue")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources", issuerAdmin,
		"cr193-trust", map[string]any{
			"name": "cr193-k8s", "method": "k8s_sat", "issuer": "https://kubernetes.default.svc",
			"audience": "trstctl", "jwks": publicJWKS,
		})
	if status != http.StatusCreated {
		t.Fatalf("issuer-admin trust setup = %d %s", status, body)
	}
	pub := sshTestPublicKey(t)
	status, _ = secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/certificates", issuer,
		"cr193-direct-control", map[string]any{
			"certificate_type": "user", "public_key": pub, "key_id": "cr193-direct",
			"principals": []string{"root"}, "ttl_seconds": 600,
		})
	if status != http.StatusForbidden {
		t.Fatalf("direct root control = %d, want 403", status)
	}
	status, _ = secretsReqKey(t, h, http.MethodPost, "/api/v1/ssh/attested-user-certs", issuer,
		"cr193-attested-root", map[string]any{
			"method": "k8s_sat", "payload_base64": base64.StdEncoding.EncodeToString([]byte(proof)),
			"public_key": pub, "key_id": "cr193-builder", "principals": []string{"root"},
			"ttl_seconds": 600,
		})
	if status != http.StatusForbidden {
		t.Errorf("attested pod name became root SSH login: status=%d, want 403", status)
	}
	if h.hasEvent(t, "ssh.attested_cert.issued") {
		t.Error("attested pod name produced an SSH issuance event")
	}
}
