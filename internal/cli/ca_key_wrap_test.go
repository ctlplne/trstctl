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

	"trstctl.com/trstctl/internal/crypto"
)

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
	locked, err := crypto.LockedKeyFromPKCS8(pkcs8)
	if err != nil {
		t.Fatal(err)
	}
	spki := append([]byte(nil), locked.Public().DER...)
	locked.Destroy()
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	offer, err := json.Marshal(map[string]any{
		"ceremony_id": "ceremony-1", "tenant_id": "tenant-a", "operation_id": "ceremony-1",
		"suite": crypto.KeyImportSuite, "public_key": importKey.Public(), "expected_public_key": spki,
		"signer_handle": "ca-hierarchy-ceremony-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	offerFile := write("offer.json", offer)
	keyFile := write("ca.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	requestFile := write("import.json", []byte(`{"ceremony_id":"ceremony-1","certificate_pem":"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n","spec":{"common_name":"root"}}`))
	outFile := filepath.Join(dir, "sealed.json")

	var stdout, stderr bytes.Buffer
	if code := runCAWrapKey([]string{"--offer", offerFile, "--key", keyFile, "--request", requestFile, "--out", outFile}, &stdout, &stderr); code != 0 {
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
		SealedKey      []byte         `json:"sealed_key"`
	}
	if err := json.Unmarshal(raw, &request); err != nil || request.CeremonyID != "ceremony-1" || request.Spec["common_name"] != "root" {
		t.Fatalf("import request = %s, %v", raw, err)
	}
	opened, err := importKey.Open(crypto.KeyImportInfo("tenant-a", "ceremony-1", spki), request.SealedKey)
	if err != nil || !bytes.Equal(opened, pkcs8) {
		t.Fatalf("the sealed key does not open to the operator's key under the offer's binding: %v", err)
	}

	otherPKCS8, err := crypto.GeneratePKCS8(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	otherKey := write("other.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherPKCS8}))
	stderr.Reset()
	if code := runCAWrapKey([]string{"--offer", offerFile, "--key", otherKey, "--request", requestFile, "--out", outFile + ".2"}, &stdout, &stderr); code == 0 || !strings.Contains(stderr.String(), "not the key") {
		t.Fatalf("wrap-key with a key that is not the certificate's = %d stderr=%s", code, stderr.String())
	}
	otherRequest := write("other-import.json", []byte(`{"ceremony_id":"ceremony-2","certificate_pem":"x","spec":{}}`))
	stderr.Reset()
	if code := runCAWrapKey([]string{"--offer", offerFile, "--key", keyFile, "--request", otherRequest, "--out", outFile + ".3"}, &stdout, &stderr); code == 0 || !strings.Contains(stderr.String(), "ceremony") {
		t.Fatalf("wrap-key with an offer for another ceremony = %d stderr=%s", code, stderr.String())
	}
}
