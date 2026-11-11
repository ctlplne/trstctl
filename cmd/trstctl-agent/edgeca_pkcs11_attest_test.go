// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/crypto/deviceattesttest"
)

// A175-L2: --edge-attest with a PKCS#11 edge key writes the complete mint
// body itself: the CSR and the token's own attestation chain of the key (read
// from the certificate objects the operator names, its leaf checked against
// the CSR), sent as pkcs11_attestation_chain_der with key_provider pkcs11.
// Before, --edge-attest refused every key but a TPM's and the operator
// assembled the PKCS#11 body by hand.
func TestEdgeAttestWritesThePKCS11MintBodyA175L2(t *testing.T) {
	dir := t.TempDir()
	provider := &edgeCLITestProvider{name: "pkcs11"}
	t.Cleanup(func() {
		if provider.key != nil {
			provider.key.Destroy()
		}
	})
	oldOpen, oldRead := openEdgeCAKeyProvider, readEdgeTokenAttestation
	t.Cleanup(func() { openEdgeCAKeyProvider, readEdgeTokenAttestation = oldOpen, oldRead })
	openEdgeCAKeyProvider = func(edgeCAOptions) (crypto.EdgeCAKeyProvider, func() error, error) {
		return provider, func() error { return nil }, nil
	}
	csrPath, handlePath := filepath.Join(dir, "edge.csr"), filepath.Join(dir, "edge.keyref.json")
	if err := runEdgeCSR(edgeCAOptions{csrMode: true, tenantID: "tenant-a", segmentID: "segment-a", commonName: "token edge CA",
		keyProvider: "pkcs11", keyGeneration: "1", keyHandleOut: handlePath, csrOut: csrPath}); err != nil {
		t.Fatalf("pkcs11 edge-csr: %v", err)
	}
	csrDER, err := os.ReadFile(csrPath) // #nosec G304 -- t.TempDir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	vendor, err := deviceattesttest.NewTokenAttestationAuthority(now, 17501752)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := vendor.AttestCSR(csrDER, now)
	if err != nil {
		t.Fatal(err)
	}
	var askedFor []byte
	readEdgeTokenAttestation = func(opts edgeCAOptions, csr []byte) ([][]byte, error) {
		if opts.pkcs11AttestationLabels == "" {
			return nil, errors.New("no labels")
		}
		askedFor = csr
		if err := deviceattest.TokenAttestationCertifiesCSR(chain[0], csr); err != nil {
			return nil, err
		}
		return chain, nil
	}
	bodyPath := filepath.Join(dir, "mint.json")
	opts := edgeCAOptions{attestMode: true, keyProvider: "pkcs11", tenantID: "tenant-a", segmentID: "segment-a", csrIn: csrPath,
		pkcs11AttestationLabels: "X.509 Certificate for PIV Attestation 9c,X.509 Certificate for PIV Attestation",
		mintRequestOut:          bodyPath, mintParentCAID: "11111111-2222-4333-8444-555555555555", mintHost: "edge-host-1", mintTTL: 24 * time.Hour}
	if err := runEdgeAttest(opts); err != nil {
		t.Fatalf("pkcs11 edge-attest: %v", err)
	}
	if string(askedFor) != string(csrDER) {
		t.Fatal("the token's attestation was not read for the CSR named")
	}
	raw, err := os.ReadFile(bodyPath) // #nosec G304 -- t.TempDir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		SegmentID   string   `json:"segment_id"`
		CAID        string   `json:"ca_id"`
		Host        string   `json:"host"`
		CSRDER      []byte   `json:"csr_der"`
		KeyProvider string   `json:"key_provider"`
		Chain       [][]byte `json:"pkcs11_attestation_chain_der"`
		TTL         int      `json:"ttl_seconds"`
		Credential  any      `json:"attestation_credential_json"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body.KeyProvider != "pkcs11" || body.SegmentID != "segment-a" || body.Host != "edge-host-1" || body.TTL != 86400 ||
		string(body.CSRDER) != string(csrDER) || len(body.Chain) != 2 || body.Credential != nil {
		t.Fatalf("mint body = %s", raw)
	}
	if attested, err := deviceattest.VerifyPKCS11TokenAttestation(body.Chain, [][]byte{vendor.RootPEM()}, body.CSRDER, now); err != nil || attested.Serial != "17501752" {
		t.Fatalf("the body's chain = %+v %v; want it to verify to the vendor root over the CSR's key", attested, err)
	}
	if info, err := os.Stat(bodyPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mint body mode = %v %v; want 0600", info, err)
	}

	// Missing pieces are refused before the token is read.
	for name, edit := range map[string]func(*edgeCAOptions){
		"no labels":    func(o *edgeCAOptions) { o.pkcs11AttestationLabels = "" },
		"no body path": func(o *edgeCAOptions) { o.mintRequestOut = "" },
		"no parent CA": func(o *edgeCAOptions) { o.mintParentCAID = "" },
	} {
		bad := opts
		edit(&bad)
		if err := runEdgeAttest(bad); err == nil || !strings.Contains(err.Error(), "requires") && !strings.Contains(err.Error(), "needs") {
			t.Fatalf("%s: %v; want refused", name, err)
		}
	}
	// A chain for another key is refused by the read and nothing is written.
	_ = os.Remove(bodyPath)
	readEdgeTokenAttestation = func(edgeCAOptions, []byte) ([][]byte, error) {
		return nil, errors.New("the token's attestation certifies a different key")
	}
	if err := runEdgeAttest(opts); err == nil || !strings.Contains(err.Error(), "different key") {
		t.Fatalf("an attestation of another key = %v; want refused", err)
	}
	if _, err := os.Stat(bodyPath); !os.IsNotExist(err) {
		t.Fatal("a mint body was written for an attestation of another key")
	}
}
