// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// TestServedAgentKeySetPublishesValidBrokerKeysA182 is the key set an
// authorization server reads to check an agent's private_key_jwt assertions:
// it holds the public key of the agent's valid broker certificate under its SPKI
// SHA-256, answers an unknown agent or tenant with the same empty set, and drops
// the key once the certificate is revoked.
func TestServedAgentKeySetPublishesValidBrokerKeysA182(t *testing.T) {
	h, owner, body := servedPublicBrokerRevocationFixture(t)
	pkcs8, err := crypto.GeneratePKCS8(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	agentKey, err := crypto.NewLockedSignerFromPKCS8(crypto.ECDSAP256, pkcs8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(agentKey.Destroy)
	body["public_key_pem"] = string(crypto.MarshalPublicKeyPEM(agentKey.Public().DER))
	issued := servedBrokerIssue(t, h, owner, "agent-key-set-issue", body, http.StatusCreated)

	keySet := func(tenant, agent string) crypto.JWKS {
		t.Helper()
		status, raw := secretsReq(t, h, http.MethodGet, "/agent-keys/"+tenant+"/"+url.PathEscape(agent)+"/jwks.json", "", nil)
		if status != http.StatusOK {
			t.Fatalf("key set %s/%s: HTTP %d %s", tenant, agent, status, raw)
		}
		var set crypto.JWKS
		if err := json.Unmarshal(raw, &set); err != nil {
			t.Fatalf("key set %s: %v", raw, err)
		}
		return set
	}
	want, err := crypto.PublicJWK(agentKey.Public(), crypto.SHA256Hex(agentKey.Public().DER))
	if err != nil {
		t.Fatal(err)
	}
	if set := keySet(h.tenant, "agent-7"); len(set.Keys) != 1 || !reflect.DeepEqual(set.Keys[0], want) {
		t.Fatalf("agent-7's key set = %+v, want its certificate key %+v", set, want)
	}
	for _, probe := range [][2]string{
		{h.tenant, "agent-unknown"},
		{"99999999-9999-4999-8999-999999999999", "agent-7"},
		{"not-a-tenant", "agent-7"},
	} {
		if set := keySet(probe[0], probe[1]); len(set.Keys) != 0 {
			t.Fatalf("key set %v = %+v, want empty", probe, set)
		}
	}
	if status, _ := secretsReq(t, h, http.MethodGet, "/agent-keys/"+h.tenant+"/agent-7", "", nil); status != http.StatusNotFound {
		t.Fatalf("a path that is not a key set: HTTP %d, want 404", status)
	}

	status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates/bulk-revoke", owner, "agent-key-set-revoke",
		map[string]any{"certificate_ids": []string{issued.CertificateID}, "reason": "keyCompromise"})
	if status != http.StatusOK {
		t.Fatalf("revoke: HTTP %d %s", status, raw)
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	if set := keySet(h.tenant, "agent-7"); len(set.Keys) != 0 {
		t.Fatalf("a revoked certificate's key is still published: %+v", set)
	}
}
