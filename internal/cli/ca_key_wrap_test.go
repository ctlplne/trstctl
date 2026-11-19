// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// CR-821: require locally configured signer trust before touching the key file.
func TestCAWrapKeyRequiresSignerPinBeforeOpeningThePrivateKey(t *testing.T) {
	dir := t.TempDir()
	offerPath, requestPath := filepath.Join(dir, "offer.json"), filepath.Join(dir, "import.json")
	const ceremony = "00000000-0000-4000-8000-000000082101"
	offer := `{"ceremony_id":"` + ceremony + `","operation_id":"` + ceremony + `","tenant_id":"00000000-0000-4000-8000-000000082102","suite":"hpke-base-mlkem768p256-hkdfsha256-aes256gcm","public_key":"AQ==","expected_public_key":"AQ=="}`
	if err := os.WriteFile(offerPath, []byte(offer), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(requestPath, []byte(`{"ceremony_id":"`+ceremony+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runCAWrapKey([]string{
		"--offer", offerPath, "--request", requestPath, "--key", filepath.Join(dir, "absent-private-file"),
	}, &stdout, &stderr)
	if code == 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "--signer-fingerprint") ||
		strings.Contains(stderr.String(), "absent-private-file") {
		t.Fatalf("wrap-key must require the trusted pin before opening any private file, exit=%d stderr=%q", code, stderr.String())
	}
}

// A128: wrap-key seals the operator's CA private key to a key offer on the
// operator's machine and writes the import request with only the sealed key;
// it refuses a private key that is not the certificate's, and an offer for a
// different ceremony than the request.
func TestCAWrapKeySealsOnlyTheCertificatesKeyToTheOffer(t *testing.T) {
	dir := t.TempDir()
	importKey, err := crypto.GenerateKeyImportKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(importKey.Destroy)
	pkcs8, err := crypto.GeneratePKCS8(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(pkcs8)
	locked, err := crypto.LockedKeyFromPKCS8(pkcs8)
	if err != nil {
		t.Fatal(err)
	}
	spki := append([]byte(nil), locked.Public().DER...)
	certDER, err := crypto.SelfSignedCACert(locked, "root", time.Hour)
	locked.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	const ceremony = "00000000-0000-4000-8000-000000082121"
	const tenant = "00000000-0000-4000-8000-000000082122"
	identity, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(identity.Destroy)
	signed, err := crypto.SignKeyImportOffer(crypto.CAKeyImportPolicy(tenant, ceremony, spki), importKey.Public(), time.Now(), identity)
	if err != nil {
		t.Fatal(err)
	}
	pin := crypto.SHA256Hex(identity.Public().DER)
	offer, err := json.Marshal(struct {
		crypto.AuthenticatedKeyImportOffer
		CeremonyID string `json:"ceremony_id"`
	}{
		AuthenticatedKeyImportOffer: signed, CeremonyID: ceremony,
	})
	if err != nil {
		t.Fatal(err)
	}
	offerFile := write("offer.json", offer)
	keyFile := write("ca.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	requestJSON, err := json.Marshal(map[string]any{
		"ceremony_id": ceremony, "certificate_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})),
		"spec": map[string]string{"common_name": "root"},
	})
	if err != nil {
		t.Fatal(err)
	}
	requestFile := write("import.json", requestJSON)
	outFile := filepath.Join(dir, "sealed.json")

	var stdout, stderr bytes.Buffer
	wrap := func(key, request, out string) int {
		stdout.Reset()
		stderr.Reset()
		return runCAWrapKey([]string{
			"--offer", offerFile, "--key", key, "--request", request, "--out", out,
			"--tenant-id", tenant, "--signer-fingerprint", pin,
		}, &stdout, &stderr)
	}
	if code := wrap(keyFile, requestFile, outFile); code != 0 {
		t.Fatalf("wrap-key = %d stderr=%s", code, stderr.String())
	}
	raw, err := os.ReadFile(outFile) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, pkcs8) || strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatal("the import request carries the plaintext key")
	}
	var request struct {
		CeremonyID     string         `json:"ceremony_id"`
		CertificatePEM string         `json:"certificate_pem"`
		Spec           map[string]any `json:"spec"`
		SealedKey      []byte         `json:"sealed_key_v2"`
	}
	if err := json.Unmarshal(raw, &request); err != nil || request.CeremonyID != ceremony || request.Spec["common_name"] != "root" {
		t.Fatalf("import request = %s, %v", raw, err)
	}
	info, err := signed.HPKEInfo()
	if err != nil {
		t.Fatal(err)
	}
	opened, err := importKey.Open(info, request.SealedKey)
	defer secret.Wipe(opened)
	if err != nil || !bytes.Equal(opened, pkcs8) {
		t.Fatalf("the sealed key does not open to the operator's key under the offer's binding: %v", err)
	}

	otherPKCS8, err := crypto.GeneratePKCS8(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(otherPKCS8)
	otherKey := write("other.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherPKCS8}))
	if code := wrap(otherKey, requestFile, outFile+".2"); code == 0 || !strings.Contains(stderr.String(), "not the key") {
		t.Fatalf("wrap-key with a key that is not the certificate's = %d stderr=%s", code, stderr.String())
	}
	otherRequest := write("other-import.json", []byte(`{"ceremony_id":"00000000-0000-4000-8000-000000082123","certificate_pem":"x","spec":{}}`))
	if code := wrap(keyFile, otherRequest, outFile+".3"); code == 0 || !strings.Contains(stderr.String(), "ceremony") {
		t.Fatalf("wrap-key with an offer for another ceremony = %d stderr=%s", code, stderr.String())
	}

	alteredRequest := func(name, field string, value any) string {
		t.Helper()
		var fields map[string]any
		if err := json.Unmarshal(requestJSON, &fields); err != nil {
			t.Fatal(err)
		}
		fields[field] = value
		raw, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		return write(name+".json", raw)
	}
	legacyOffer := bytes.Replace(offer, []byte(crypto.AuthenticatedKeyImportSuite), []byte(crypto.KeyImportSuite), 1)
	for _, tc := range []struct {
		name, offer, request, tenant, pin, want string
	}{
		{"legacy-offer", write("legacy-offer.json", legacyOffer), requestFile, tenant, pin, "authenticated key import v2"},
		{"other-pin", offerFile, requestFile, tenant, crypto.SHA256Hex([]byte("a separate signer identity")), "trusted pin"},
		{"other-tenant", offerFile, requestFile, "00000000-0000-4000-8000-000000082125", pin, "different tenant"},
		{"other-cert", offerFile, alteredRequest("changed-certificate", "certificate_pem", "unavailable"), tenant, pin, "first PEM block"},
		{"legacy-field", offerFile, alteredRequest("legacy-field", "sealed_key", nil), tenant, pin, "already carries a sealed key"},
		{"legacy-case-field", offerFile, alteredRequest("legacy-case-field", "SEALED_KEY", nil), tenant, pin, "already carries a sealed key"},
		{"v2-field", offerFile, alteredRequest("v2-field", "sealed_key_v2", nil), tenant, pin, "already carries a sealed key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildCAKeyImportRequest(tc.offer, filepath.Join(dir, "unavailable-private-file"), tc.request, tc.tenant, tc.pin)
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "read private key") {
				t.Fatalf("wrapper must refuse invalid public input before opening the private file: %v", err)
			}
		})
	}
}
