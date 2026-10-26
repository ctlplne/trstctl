// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

type servedCAKeyImportOffer struct {
	CeremonyID        string `json:"ceremony_id"`
	TenantID          string `json:"tenant_id"`
	OperationID       string `json:"operation_id"`
	Suite             string `json:"suite"`
	PublicKey         []byte `json:"public_key"`
	ExpectedPublicKey []byte `json:"expected_public_key"`
	SignerHandle      string `json:"signer_handle"`
}

// A128 through the served binary: an operator's existing CA, with the private
// key it already has, becomes a signer-held authority. Two custodians approve
// the chain and profile; the signer offers a one-time import key; the operator
// seals the key to it off-box; the import opens it inside the signer, which
// must hold the certificate's key; and the imported authority issues leaves
// that chain to the operator's own certificate. The control plane only ever
// relays sealed bytes.
func TestServedCAKeyImportTakesAnOperatorsCAKeyIntoTheSigner(t *testing.T) {
	ctx := context.Background()
	h := newOperatingServedHarness(t, config.Protocols{})
	operator := seedServedAPIToken(t, ctx, h.store, h.tenant, "ca-key-import-operator", []string{"issuers:write", "issuers:read", "certs:issue"})
	approver := seedServedAPIToken(t, ctx, h.store, h.tenant, "ca-key-import-approver", []string{"issuers:write", "issuers:read", "certs:issue"})

	// The operator's existing root CA and its private key, outside trstctl.
	rootPKCS8, err := crypto.GeneratePKCS8(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(rootPKCS8)
	rootKey, err := crypto.LockedKeyFromPKCS8(rootPKCS8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rootKey.Destroy)
	profile := crypto.HierarchyCAProfile{
		CommonName: "operator existing root", MaxPathLen: 1, TTL: 365 * 24 * time.Hour,
		PermittedDNSDomains: []string{"keyimport.example.test"}, EKUs: []string{"serverAuth"},
	}
	root, err := crypto.SelfSignedHierarchyCA(rootKey, profile)
	if err != nil {
		t.Fatal(err)
	}
	spec := map[string]any{
		"common_name": profile.CommonName, "max_path_len": profile.MaxPathLen,
		"ttl_seconds": int64(profile.TTL.Seconds()), "permitted_dns_domains": profile.PermittedDNSDomains,
		"extended_key_usages": profile.EKUs, "signature_algorithm": "ecdsa-p256",
	}
	certificatePEM := string(root.CertificatePEM)
	ceremony := createCACeremonyWithCertificate(t, h, operator, "import_ca_key", certificatePEM, spec, 1, "ca-key-import-ceremony")
	body := map[string]any{"ceremony_id": ceremony.ID, "certificate_pem": certificatePEM, "spec": spec}
	if code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/imported/key-offer", operator, "ca-key-import-offer-early", body); code != http.StatusConflict {
		t.Fatalf("key offer before quorum = %d body=%s; want 409", code, raw)
	}
	approveCACeremony(t, h, approver, ceremony.ID, 1, "ca-key-import-approval")

	code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/imported/key-offer", operator, "ca-key-import-offer", body)
	if code != http.StatusOK {
		t.Fatalf("key offer = %d body=%s; want 200", code, raw)
	}
	var offer servedCAKeyImportOffer
	if err := json.Unmarshal(raw, &offer); err != nil {
		t.Fatalf("decode offer: %v body=%s", err, raw)
	}
	if offer.Suite != crypto.KeyImportSuite || len(offer.PublicKey) == 0 || offer.TenantID != h.tenant ||
		offer.OperationID != ceremony.ID || !bytes.Equal(offer.ExpectedPublicKey, rootKey.Public().DER) || offer.SignerHandle == "" {
		t.Fatalf("key offer = %+v", offer)
	}

	// A key that is not the certificate's is refused inside the signer.
	wrongPKCS8, err := crypto.GeneratePKCS8(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	wrongSealed, err := crypto.SealKeyImport(offer.PublicKey, crypto.KeyImportInfo(offer.TenantID, offer.OperationID, offer.ExpectedPublicKey), wrongPKCS8)
	if err != nil {
		t.Fatal(err)
	}
	wrong := map[string]any{"ceremony_id": ceremony.ID, "certificate_pem": certificatePEM, "spec": spec, "sealed_key": wrongSealed}
	if code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/imported/key", operator, "ca-key-import-wrong", wrong); code != http.StatusUnprocessableEntity {
		t.Fatalf("import of a key that is not the certificate's = %d body=%s; want 422", code, raw)
	}

	// The operator seals the real key off-box.
	sealed, err := crypto.SealKeyImport(offer.PublicKey, crypto.KeyImportInfo(offer.TenantID, offer.OperationID, offer.ExpectedPublicKey), rootPKCS8)
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"ceremony_id": ceremony.ID, "certificate_pem": certificatePEM, "spec": spec, "sealed_key": sealed}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, rootPKCS8) || strings.Contains(string(encoded), base64.StdEncoding.EncodeToString(rootPKCS8)) {
		t.Fatal("the import request carries the plaintext private key")
	}
	code, raw = doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/imported/key", operator, "ca-key-import", request)
	if code != http.StatusCreated {
		t.Fatalf("import CA key = %d body=%s; want 201", code, raw)
	}
	var imported servedCAAuthority
	if err := json.Unmarshal(raw, &imported); err != nil {
		t.Fatalf("decode imported authority: %v body=%s", err, raw)
	}
	if imported.Status != "active" || imported.Kind != "root" || imported.SignerHandle != offer.SignerHandle ||
		imported.PossessionProof != "signer_challenge" {
		t.Fatalf("imported authority = %+v", imported)
	}

	// The signer holds the operator's key: it reports that public key, and
	// leaves it issues chain to the operator's own certificate.
	remote, err := h.signer.Client().SignerForHandle(ctx, offer.SignerHandle)
	if err != nil || !bytes.Equal(remote.Public().DER, rootKey.Public().DER) {
		t.Fatalf("signer holds %v for the imported handle, %v; want the operator's key", remote, err)
	}
	leaf := issueHierarchyLeaf(t, h, operator, imported.ID, "leaf.keyimport.example.test", "ca-key-import-leaf")
	if err := crypto.VerifyLeafSignedByCA(caCertDER(t, []byte(leaf.CertificatePEM)), root.CertificateDER); err != nil {
		t.Fatalf("a leaf of the imported authority does not chain to the operator's certificate: %v", err)
	}
	if code, raw := doBearer(t, h.ts, http.MethodPost, "/api/v1/ca/authorities/imported/key", operator, "ca-key-import-again", request); code != http.StatusConflict {
		t.Fatalf("a second import under the used ceremony = %d body=%s; want 409", code, raw)
	}
}
