// SPDX-License-Identifier: BUSL-1.1

//go:build pkcs11cgo && cgo

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/crypto/deviceattesttest"
)

// A175-L2 against a real PKCS#11 module: edge-csr generates the edge key on
// SoftHSM, a stand-in vendor hierarchy attests it and the chain is stored on
// the token under the labels a YubiKey's PIV module uses (with pkcs11-tool,
// as an operator would), and edge-attest reads it from the token and writes
// the complete PKCS#11 mint body. SoftHSM has no attestation of its own: this
// proves the CLI's read and the body, not a vendor's hardware.
// softHSMEdgeLabels prefixes the labels of the token objects this test creates.
const softHSMEdgeLabels = "trstctl-edge-a175l2"

func TestSoftHSMEdgeAttestWritesThePKCS11MintBodyA175L2(t *testing.T) {
	modulePath := os.Getenv("TRSTCTL_SOFTHSM_MODULE")
	tokenLabel := os.Getenv("TRSTCTL_SOFTHSM_TOKEN_LABEL")
	userPIN := os.Getenv("TRSTCTL_SOFTHSM_USER_PIN")
	if modulePath == "" || tokenLabel == "" || userPIN == "" {
		t.Skip("TRSTCTL_SOFTHSM_MODULE, TRSTCTL_SOFTHSM_TOKEN_LABEL, and TRSTCTL_SOFTHSM_USER_PIN are required")
	}
	dir := t.TempDir()
	pinFile := filepath.Join(dir, "user.pin")
	if err := os.WriteFile(pinFile, []byte(userPIN+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	device := edgeCAOptions{
		tenantID: "tenant-a", segmentID: "segment-a", keyProvider: "pkcs11",
		pkcs11Module: modulePath, pkcs11Token: tokenLabel, pkcs11PINFile: pinFile, pkcs11KeyLabelPrefix: softHSMEdgeLabels,
	}
	csrPath, handlePath := filepath.Join(dir, "edge.csr"), filepath.Join(dir, "edge.keyref.json")
	csrOpts := device
	csrOpts.csrMode, csrOpts.commonName, csrOpts.keyGeneration = true, "softhsm edge CA", "1"
	csrOpts.keyHandleOut, csrOpts.csrOut = handlePath, csrPath
	if err := runEdgeCSR(csrOpts); err != nil {
		t.Fatalf("edge-csr on SoftHSM: %v", err)
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
	const leafLabel, deviceLabel = "X.509 Certificate for PIV Attestation 9c", "X.509 Certificate for PIV Attestation"
	for i, object := range []struct {
		label string
		der   []byte
	}{{leafLabel, chain[0]}, {deviceLabel, chain[1]}} {
		path := filepath.Join(dir, fmt.Sprintf("attestation-%d.der", i))
		if err := os.WriteFile(path, object.der, 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("pkcs11-tool", "--module", modulePath, "--token-label", tokenLabel, "--login", "--pin", userPIN, // #nosec G204 -- fixed pkcs11-tool invocation inside the SoftHSM test container (CWE-78)
			"--write-object", path, "--type", "cert", "--label", object.label, "--id", fmt.Sprintf("a1750%d", i+2)).CombinedOutput()
		if err != nil {
			t.Fatalf("store %q on the token: %v\n%s", object.label, err, out)
		}
	}

	bodyPath := filepath.Join(dir, "mint.json")
	attestOpts := device
	attestOpts.attestMode, attestOpts.csrIn, attestOpts.mintRequestOut = true, csrPath, bodyPath
	attestOpts.pkcs11AttestationLabels = leafLabel + "," + deviceLabel
	attestOpts.mintParentCAID, attestOpts.mintHost, attestOpts.mintTTL = "11111111-2222-4333-8444-555555555555", "edge-host-1", 24*time.Hour
	if err := runEdgeAttest(attestOpts); err != nil {
		t.Fatalf("edge-attest on SoftHSM: %v", err)
	}
	raw, err := os.ReadFile(bodyPath) // #nosec G304 -- t.TempDir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		SegmentID   string   `json:"segment_id"`
		CAID        string   `json:"ca_id"`
		Host        string   `json:"host"`
		TTLSeconds  int      `json:"ttl_seconds"`
		KeyProvider string   `json:"key_provider"`
		CSRDER      []byte   `json:"csr_der"`
		Chain       [][]byte `json:"pkcs11_attestation_chain_der"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body.KeyProvider != "pkcs11" || body.SegmentID != "segment-a" || body.Host != "edge-host-1" || body.TTLSeconds != 86400 ||
		string(body.CSRDER) != string(csrDER) {
		t.Fatalf("mint body = provider %q segment %q host %q ttl %d, CSR equal %t", body.KeyProvider, body.SegmentID, body.Host, body.TTLSeconds, string(body.CSRDER) == string(csrDER))
	}
	if len(body.Chain) != 2 || !slices.Equal(body.Chain[0], chain[0]) || !slices.Equal(body.Chain[1], chain[1]) {
		t.Fatalf("the mint body's chain is not the token's attestation, leaf first (%d certificates)", len(body.Chain))
	}
	attested, err := deviceattest.VerifyPKCS11TokenAttestation(body.Chain, [][]byte{vendor.RootPEM()}, body.CSRDER, now)
	if err != nil || attested.Serial != "17501752" {
		t.Fatalf("the brain's verification of the body = %+v, %v", attested, err)
	}
	if info, err := os.Stat(bodyPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mint body mode = %v, %v; want 0600", info, err)
	}
	t.Log("SOFTHSM_EDGE_ATTEST_PKCS11_OK")
}
