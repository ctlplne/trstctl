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

// A175-L3 Done-when: a token that attests in its own format, not X.509
// certificate objects, makes an edge CA key hardware-attested on the same
// evidence seam. A SmartCard-HSM stand-in built to BSI TR-03110 answers key
// generation with an authenticated CV request; the segment pins the vendor's
// CV root as a "CV CERTIFICATE" PEM block. A mint with that attestation is
// hardware_key_attested and names the device serial and the root; an
// attestation of another key, from a card under an unpinned root, or sent
// together with an X.509 chain is refused; a malformed CV root is refused
// when the segment is saved.
func TestServedSmartCardHSMEdgeKeyAttestedByItsDeviceA175L3(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := context.Background()
	operator := seedServedAPIToken(t, ctx, h.store, h.tenant, "edge-operator", []string{"issuers:write", "issuers:read", "certs:issue"})
	approverOne := seedServedAPIToken(t, ctx, h.store, h.tenant, "custodian-one", []string{"issuers:write", "issuers:read"})
	approverTwo := seedServedAPIToken(t, ctx, h.store, h.tenant, "custodian-two", []string{"issuers:write", "issuers:read"})
	rootSpec := map[string]any{
		"common_name": "trstctl smartcard-hsm edge parent", "max_path_len": 1, "ttl_seconds": int64((90 * 24 * time.Hour).Seconds()),
		"permitted_dns_domains": []string{"example.test"}, "extended_key_usages": []string{"serverAuth"}, "signature_algorithm": "ecdsa-p256",
	}
	ceremony := createCACeremony(t, h, operator, "create_root", "", rootSpec, 2, "a175l3-root-ceremony")
	approveCACeremony(t, h, approverOne, ceremony.ID, 1, "a175l3-root-approve-1")
	approveCACeremony(t, h, approverTwo, ceremony.ID, 2, "a175l3-root-approve-2")
	root := createRootCA(t, h, operator, ceremony.ID, rootSpec, "a175l3-root-create")
	segment, err := h.store.UpsertDiscoverySegment(ctx, h.tenant, store.DiscoverySegment{Name: "edge-smartcard-lab", Ranges: []string{"10.17.6.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	host, err := deviceattesttest.NewTPMIdentity(now)
	if err != nil {
		t.Fatal(err)
	}
	card, err := deviceattesttest.NewSmartCardHSM("DECC0175")
	if err != nil {
		t.Fatal(err)
	}
	otherCard, err := deviceattesttest.NewSmartCardHSM("DECC0999")
	if err != nil {
		t.Fatal(err)
	}
	vendor, err := deviceattesttest.NewTokenAttestationAuthority(now, 17500175)
	if err != nil {
		t.Fatal(err)
	}
	setPolicy := func(key string, roots ...[]byte) (int, []byte) {
		pemRoots := make([]string, 0, len(roots))
		for _, r := range roots {
			pemRoots = append(pemRoots, string(r))
		}
		return doBearer(t, h.ts, http.MethodPut, "/api/v1/edge/segments/"+segment.ID, operator, key, map[string]any{
			"enabled": true, "attestation_roots_pem": []string{string(host.RootPEM())},
			"permitted_dns_domains": []string{"edge.example.test"}, "allowed_key_providers": []string{"tpm2", "pkcs11"},
			"pkcs11_attestation_roots_pem": pemRoots,
		})
	}
	if code, body := setPolicy("a175l3-policy", card.RootPEM(), vendor.RootPEM()); code != http.StatusOK {
		t.Fatalf("pin the card's CV root beside an X.509 vendor root = %d %s", code, body)
	}
	if code, body := setPolicy("a175l3-policy-garbled", []byte("-----BEGIN CV CERTIFICATE-----\nfwEA\n-----END CV CERTIFICATE-----\n")); code != http.StatusBadRequest ||
		!strings.Contains(string(body), "CV certificate") {
		t.Fatalf("a malformed CV root = %d %s", code, body)
	}

	csr, request, err := card.GenerateKey("vault-07 edge CA")
	if err != nil {
		t.Fatal(err)
	}
	mint := func(key string, csr []byte, attestation map[string]any, chain [][]byte) (int, []byte) {
		t.Helper()
		credential, err := host.CredentialJSON(crypto.EdgeAttestationChallenge(h.tenant, segment.ID, csr))
		if err != nil {
			t.Fatal(err)
		}
		body := map[string]any{"segment_id": segment.ID, "ca_id": root.ID, "host": "vault-07", "common_name": "vault-07 edge CA",
			"ttl_seconds": 3600, "csr_der": csr, "attestation_credential_json": credential, "key_provider": "pkcs11"}
		if attestation != nil {
			body["smartcard_hsm_attestation"] = attestation
		}
		if chain != nil {
			body["pkcs11_attestation_chain_der"] = chain
		}
		return doBearer(t, h.ts, http.MethodPost, "/api/v1/edge/delegations", operator, key, body)
	}
	evidence := func(c *deviceattesttest.SmartCardHSM, request []byte) map[string]any {
		return map[string]any{"authenticated_request": request, "device_cvc": c.DeviceCVC, "dica_cvc": c.DICACVC}
	}
	code, body := mint("a175l3-mint", csr, evidence(card, request), nil)
	var minted struct {
		ID               string `json:"id"`
		KeyStorage       string `json:"key_storage"`
		KeyExportable    bool   `json:"key_exportable"`
		CustodyAssurance string `json:"custody_assurance"`
		TokenAttestation *struct {
			RootSHA256 string `json:"root_sha256"`
			Serial     string `json:"serial"`
		} `json:"token_attestation"`
	}
	if code != http.StatusCreated || json.Unmarshal(body, &minted) != nil || minted.KeyStorage != "pkcs11" || minted.KeyExportable ||
		minted.CustodyAssurance != "hardware_key_attested" || minted.TokenAttestation == nil || minted.TokenAttestation.Serial != "DECC0175" ||
		len(minted.TokenAttestation.RootSHA256) != 64 {
		t.Fatalf("SmartCard-HSM attested mint = %d %s", code, body)
	}
	if code, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/edge/delegations/"+minted.ID, operator, "", nil); code != http.StatusOK ||
		!strings.Contains(string(body), `"serial":"DECC0175"`) {
		t.Fatalf("delegation detail = %d %s", code, body)
	}

	// An attestation of another key is refused.
	otherCSR, _, err := card.GenerateKey("another key")
	if err != nil {
		t.Fatal(err)
	}
	if code, body := mint("a175l3-mint-other-key", otherCSR, evidence(card, request), nil); code != http.StatusForbidden ||
		!strings.Contains(string(body), "different key") {
		t.Fatalf("attestation of another key = %d %s", code, body)
	}
	// A card under a root the segment did not pin is refused.
	untrustedCSR, untrusted, err := otherCard.GenerateKey("untrusted card key")
	if err != nil {
		t.Fatal(err)
	}
	if code, body := mint("a175l3-mint-untrusted", untrustedCSR, evidence(otherCard, untrusted), nil); code != http.StatusForbidden ||
		!strings.Contains(string(body), "not certified by a pinned root") {
		t.Fatalf("unpinned card = %d %s", code, body)
	}
	// One attestation form at a time.
	chain, err := vendor.AttestCSR(csr, now)
	if err != nil {
		t.Fatal(err)
	}
	if code, body := mint("a175l3-mint-both", csr, evidence(card, request), chain); code != http.StatusBadRequest ||
		!strings.Contains(string(body), "not both") {
		t.Fatalf("both attestation forms = %d %s", code, body)
	}
	// The X.509 vendor root pinned beside the CV root still works.
	if code, body := mint("a175l3-mint-x509", csr, nil, chain); code != http.StatusCreated || !strings.Contains(string(body), `"custody_assurance":"hardware_key_attested"`) {
		t.Fatalf("X.509 token chain beside a CV root = %d %s", code, body)
	}
}
