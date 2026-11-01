// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/deviceattesttest"
	"trstctl.com/trstctl/internal/store"
)

// A175 Done-when: a PKCS#11 edge key is recorded as hardware-attested only
// on the token's own attestation. A segment pins its token vendor's
// attestation root; a host that sends the token's chain certifying the CSR's
// key gets hardware_key_attested PKCS#11 custody with the device serial and
// key policies. A chain for another key, or one that does not reach a pinned
// vendor root, is refused; a segment that requires token attestation refuses
// a request without one; without the requirement a request without one keeps
// the operator-claim label.
func TestServedPKCS11EdgeKeyAttestedByItsToken(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := context.Background()
	operator := seedServedAPIToken(t, ctx, h.store, h.tenant, "edge-operator", []string{"issuers:write", "issuers:read", "certs:issue"})
	approverOne := seedServedAPIToken(t, ctx, h.store, h.tenant, "custodian-one", []string{"issuers:write", "issuers:read"})
	approverTwo := seedServedAPIToken(t, ctx, h.store, h.tenant, "custodian-two", []string{"issuers:write", "issuers:read"})
	rootSpec := map[string]any{
		"common_name": "trstctl token edge parent", "max_path_len": 1, "ttl_seconds": int64((90 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"example.test"}, "extended_key_usages": []string{"serverAuth"}, "signature_algorithm": "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h, operator, "create_root", "", rootSpec, 2, "a175-root-ceremony")
	approveCACeremony(t, h, approverOne, ceremony.ID, 1, "a175-root-approve-1")
	approveCACeremony(t, h, approverTwo, ceremony.ID, 2, "a175-root-approve-2")
	root := createRootCA(t, h, operator, ceremony.ID, rootSpec, "a175-root-create")
	segment, err := h.store.UpsertDiscoverySegment(ctx, h.tenant, store.DiscoverySegment{Name: "edge-token-lab", Ranges: []string{"10.17.5.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	host, err := deviceattesttest.NewTPMIdentity(now)
	if err != nil {
		t.Fatal(err)
	}
	vendor, err := deviceattesttest.NewTokenAttestationAuthority(now, 17500175)
	if err != nil {
		t.Fatal(err)
	}
	otherVendor, err := deviceattesttest.NewTokenAttestationAuthority(now, 99)
	if err != nil {
		t.Fatal(err)
	}
	setPolicy := func(key string, roots [][]byte, require bool) {
		t.Helper()
		pem := make([]string, 0, len(roots))
		for _, r := range roots {
			pem = append(pem, string(r))
		}
		code, body := doBearer(t, h.ts, http.MethodPut, "/api/v1/edge/segments/"+segment.ID, operator, key, map[string]any{
			"enabled": true, "attestation_roots_pem": []string{string(host.RootPEM())},
			"permitted_dns_domains": []string{"edge.example.test"}, "allowed_key_providers": []string{"tpm2", "pkcs11"},
			"pkcs11_attestation_roots_pem": pem, "require_pkcs11_attestation": require,
		})
		if code != http.StatusOK {
			t.Fatalf("policy %s = %d %s", key, code, body)
		}
	}
	// The token key: the stand-in vendor certifies the CSR's key, the way a
	// token's module exposes its attestation of a key it generated.
	_, tokenCSR, err := crypto.GenerateEdgeCAKeyAndCSR("token edge CA")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := host.CredentialJSON(crypto.EdgeAttestationChallenge(h.tenant, segment.ID, tokenCSR))
	if err != nil {
		t.Fatal(err)
	}
	chain, err := vendor.AttestCSR(tokenCSR, now)
	if err != nil {
		t.Fatal(err)
	}
	mint := func(key string, csr []byte, chain [][]byte) (int, []byte) {
		body := map[string]any{"segment_id": segment.ID, "ca_id": root.ID, "host": "vault-07", "common_name": "vault-07 edge CA",
			"ttl_seconds": 3600, "csr_der": csr, "attestation_credential_json": credential, "key_provider": "pkcs11"}
		if chain != nil {
			body["pkcs11_attestation_chain_der"] = chain
		}
		return doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/delegations", operator, key, body)
	}
	type tokenView struct {
		ID               string `json:"id"`
		KeyProvider      string `json:"key_provider"`
		KeyStorage       string `json:"key_storage"`
		KeyExportable    bool   `json:"key_exportable"`
		CustodyAssurance string `json:"custody_assurance"`
		TokenAttestation *struct {
			RootSHA256  string `json:"root_sha256"`
			Serial      string `json:"serial"`
			PINPolicy   string `json:"pin_policy"`
			TouchPolicy string `json:"touch_policy"`
		} `json:"token_attestation"`
	}

	setPolicy("a175-policy-pinned", [][]byte{vendor.RootPEM()}, false)
	code, body := mint("a175-mint-attested", tokenCSR, chain)
	var attested tokenView
	if code != http.StatusCreated || json.Unmarshal(body, &attested) != nil {
		t.Fatalf("token-attested mint = %d %s", code, body)
	}
	if attested.KeyProvider != "pkcs11" || attested.KeyStorage != "pkcs11" || attested.KeyExportable ||
		attested.CustodyAssurance != "hardware_key_attested" || attested.TokenAttestation == nil ||
		attested.TokenAttestation.Serial != "17500175" || attested.TokenAttestation.PINPolicy != "once" ||
		attested.TokenAttestation.TouchPolicy != "never" || len(attested.TokenAttestation.RootSHA256) != 64 {
		t.Fatalf("token custody evidence = %+v / %s", attested, body)
	}
	code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/edge/delegations/"+attested.ID, operator, "", nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"serial":"17500175"`) {
		t.Fatalf("delegation detail = %d %s", code, body)
	}

	// A chain certifying another key is refused.
	_, otherCSR, err := crypto.GenerateEdgeCAKeyAndCSR("other token key")
	if err != nil {
		t.Fatal(err)
	}
	otherChain, err := vendor.AttestCSR(otherCSR, now)
	if err != nil {
		t.Fatal(err)
	}
	if code, body := mint("a175-mint-other-key", tokenCSR, otherChain); code != http.StatusForbidden || !strings.Contains(string(body), "different key") {
		t.Fatalf("chain for another key = %d %s", code, body)
	}
	// A chain from a vendor the segment did not pin is refused.
	untrusted, err := otherVendor.AttestCSR(tokenCSR, now)
	if err != nil {
		t.Fatal(err)
	}
	if code, body := mint("a175-mint-untrusted", tokenCSR, untrusted); code != http.StatusForbidden || !strings.Contains(string(body), "pinned vendor root") {
		t.Fatalf("unpinned vendor = %d %s", code, body)
	}
	// Without a chain: the operator-claim label, or a refusal where required.
	var claimed tokenView
	if code, body := mint("a175-mint-claim", tokenCSR, nil); code != http.StatusCreated || json.Unmarshal(body, &claimed) != nil ||
		claimed.CustodyAssurance != "host_attested_operator_claim" || claimed.TokenAttestation != nil {
		t.Fatalf("mint without a chain = %d %s", code, body)
	}
	setPolicy("a175-policy-required", [][]byte{vendor.RootPEM()}, true)
	if code, body := mint("a175-mint-required", tokenCSR, nil); code != http.StatusForbidden || !strings.Contains(string(body), "token's attestation") {
		t.Fatalf("required attestation missing = %d %s", code, body)
	}
	code, body = doBearer(t, h.ts, http.MethodGet, "/api/v1/edge/segments", operator, "", nil)
	var policies struct {
		Items []struct {
			SegmentID                string `json:"segment_id"`
			PKCS11AttestationRoots   int    `json:"pkcs11_attestation_roots"`
			RequirePKCS11Attestation bool   `json:"require_pkcs11_attestation"`
		} `json:"items"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &policies) != nil {
		t.Fatalf("policy list = %d %s", code, body)
	}
	found := false
	for _, p := range policies.Items {
		if p.SegmentID == segment.ID {
			found = p.PKCS11AttestationRoots == 1 && p.RequirePKCS11Attestation
		}
	}
	if !found {
		t.Fatalf("policy view does not show one pinned vendor root and the requirement: %s", body)
	}
	// Requiring attestation needs a pinned vendor root.
	code, body = doBearer(t, h.ts, http.MethodPut, "/api/v1/edge/segments/"+segment.ID, operator, "a175-policy-no-roots", map[string]any{
		"enabled": true, "attestation_roots_pem": []string{string(host.RootPEM())}, "allowed_key_providers": []string{"tpm2", "pkcs11"},
		"permitted_dns_domains": []string{"edge.example.test"}, "require_pkcs11_attestation": true,
	})
	if code != http.StatusBadRequest || !strings.Contains(string(body), "pkcs11_attestation_roots_pem") {
		t.Fatalf("require without roots = %d %s", code, body)
	}
}
