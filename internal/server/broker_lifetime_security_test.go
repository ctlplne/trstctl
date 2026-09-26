// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/base64"
	"encoding/pem"
	"math"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// The ordinary operator's exact lifetime must reach the real signer, not only
// survive JSON decoding. Verify the actual certificate and the served receipt.
func TestServedBrokerPreservesRequestedLifetime(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AgentBroker = AgentBrokerConfig{
			Enabled: true, TrustDomain: "served.test", DefaultTTL: 10 * time.Minute,
			MaxTTL: time.Hour, PolicyModule: servedBrokerAllowPolicy,
			Attestors: []attest.Attestor{servedBrokerAttestor{}},
		}
	})
	token := seedScopedToken(t, h.store, h.tenant, "certs:issue", "certs:read")
	publicKey := servedAttestedPublicKeyPEM(t)
	for _, tc := range []struct {
		name    string
		seconds int64
		want    time.Duration
	}{
		{"two-minutes", 120, 2 * time.Minute},
		{"fifteen-minutes", 900, 15 * time.Minute},
		{"default", 0, 10 * time.Minute},
		{"at-policy-maximum", 3600, time.Hour},
		{"above-policy-maximum", 3601, time.Hour},
		{"int64-overflow-cannot-change-policy", math.MaxInt64, time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := time.Now().UTC()
			issued := servedBrokerIssue(t, h, token, "broker-lifetime-"+tc.name, map[string]any{
				"agent_id": "agent-7", "method": "stub_broker",
				"payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine")),
				"public_key_pem": publicKey, "scopes": []string{"tool:inventory.read"},
				"ttl_seconds": tc.seconds,
			}, http.StatusCreated)
			after := time.Now().UTC()
			block, rest := pem.Decode([]byte(issued.CertificatePEM))
			if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
				t.Fatal("issued response is not exactly one public certificate")
			}
			info, err := certinfo.Inspect(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if !info.NotAfter.Equal(issued.NotAfter) {
				t.Fatal("served deadline differs from the signed certificate")
			}
			if info.NotAfter.Before(before.Add(tc.want-time.Second)) || info.NotAfter.After(after.Add(tc.want)) {
				t.Fatalf("requested %d seconds, effective policy %s: signed deadline %s is not in [%s, %s]", tc.seconds, tc.want, info.NotAfter, before.Add(tc.want-time.Second), after.Add(tc.want))
			}
		})
	}
}

func TestServedBrokerRejectsExtraPublicKeyMaterial(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AgentBroker = AgentBrokerConfig{Enabled: true, TrustDomain: "served.test", PolicyModule: servedBrokerAllowPolicy, Attestors: []attest.Attestor{servedBrokerAttestor{}}}
	})
	token := seedScopedToken(t, h.store, h.tenant, "certs:issue")
	key := servedAttestedPublicKeyPEM(t)
	for name, publicKey := range map[string]string{
		"two-keys":      key + key,
		"trailing-data": key + "unexpected trailing material",
		"leading-data":  "unexpected leading material\n" + key,
	} {
		t.Run(name, func(t *testing.T) {
			servedBrokerIssue(t, h, token, "broker-key-confusion-"+name, map[string]any{
				"agent_id": "agent-7", "method": "stub_broker", "payload_base64": "Z2VudWluZQ==",
				"public_key_pem": publicKey, "scopes": []string{"tool:inventory.read"},
			}, http.StatusBadRequest)
		})
	}
	if h.hasEvent(t, "certificate.recorded") {
		t.Fatal("ambiguous public-key input reached issuance")
	}
}

// Production config cannot inject in-process test attestors. The enabled broker
// must boot with tenant-managed public trust and refuse requests until configured.
func TestServedBrokerBootsWithoutProcessAttestorsAndRefusesMissingTenantTrust(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AgentBroker = AgentBrokerConfig{Enabled: true, TrustDomain: "served.test", PolicyModule: servedBrokerAllowPolicy}
	})
	token := seedScopedToken(t, h.store, h.tenant, "certs:issue")
	servedBrokerIssue(t, h, token, "broker-no-tenant-trust", map[string]any{
		"agent_id": "agent-7", "method": "k8s_sat", "payload_base64": "Z2VudWluZQ==",
		"public_key_pem": servedAttestedPublicKeyPEM(t), "scopes": []string{"tool:inventory.read"},
	}, http.StatusUnprocessableEntity)
	if h.hasEvent(t, "certificate.recorded") {
		t.Fatal("missing tenant trust reached issuance")
	}
}
