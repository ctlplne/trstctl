// SPDX-License-Identifier: LicenseRef-trstctl-EE

//go:build pkcs11cgo && cgo

package signerwiring_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/managedkeys/signerwiring"
	"trstctl.com/trstctl/internal/codesign"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

const (
	codeSigningTenantA = "33333333-3333-4333-8333-333333333333"
	codeSigningTenantB = "44444444-4444-4444-8444-444444444444"
)

type codeSigningKeys map[string]crypto.DigestSigner

func (k codeSigningKeys) Signer(_ string, keyID string) (crypto.DigestSigner, error) {
	signer, ok := k[keyID]
	if !ok {
		return nil, errors.New("no such key")
	}
	return signer, nil
}

// P9 against SoftHSM: a code-signing key generated in the token through the
// signer's PKCS#11 managed-key provider signs a certificate request and code
// digests inside the token, for the code-signing purpose, with an independent
// authorization per signature. A command signed twice gets the same signature
// from the signer's journal, the command cannot sign another digest, and
// another tenant cannot use the key. (The PKCS#11 provider generates RSA-2048
// keys.)
func TestSoftHSMCodeSigningKeyP9(t *testing.T) {
	modulePath := os.Getenv("TRSTCTL_SOFTHSM_MODULE")
	tokenLabel := os.Getenv("TRSTCTL_SOFTHSM_TOKEN_LABEL")
	userPIN := os.Getenv("TRSTCTL_SOFTHSM_USER_PIN")
	if modulePath == "" || tokenLabel == "" || userPIN == "" {
		t.Skip("TRSTCTL_SOFTHSM_MODULE, TRSTCTL_SOFTHSM_TOKEN_LABEL and TRSTCTL_SOFTHSM_USER_PIN are required")
	}
	dir := t.TempDir()
	pinFile := filepath.Join(dir, "pkcs11-pin")
	if err := os.WriteFile(pinFile, []byte(userPIN+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "managed-keys.json")
	body := `{"enabled":true,"provider":"pkcs11","pkcs11":{"module_path":"` + modulePath + `","token_label":"` + tokenLabel +
		`","user_pin_file":"` + pinFile + `","key_label_prefix":"trstctl-p9"}}`
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	option, err := signerwiring.ProviderOption(config, filepath.Join(dir, "journal"))
	if err != nil {
		t.Fatalf("a signer with the SoftHSM provider: %v", err)
	}
	secretKey, err := crypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := crypto.NewSignAuthorizer(secretKey)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "signer.sock")
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		served <- signing.ServeServerWithOptions(ctx, socket, signing.NewServer(option, signing.WithAuthorizer(authorizer)), signing.ServeOptions{})
	}()
	client, err := signing.DialReady(ctx, socket, 10*time.Second)
	if err != nil {
		cancel()
		t.Fatalf("dial the signer: %v", err)
	}
	defer func() {
		_ = client.Close()
		cancel()
		<-served
	}()

	created, err := client.ManageKey(ctx, signing.ManagedKeyCommand{
		TenantID: codeSigningTenantA, Provider: "pkcs11", OperationID: "p9-generate-code-signing-key",
		Action: signing.ManagedKeyGenerate, Algorithm: crypto.RSA2048,
	})
	if err != nil || created.Provider != "pkcs11" || created.KeyID == "" || len(created.PublicDER) == 0 {
		t.Fatalf("the code-signing key in SoftHSM = %+v, %v", created, err)
	}
	signer, err := client.SignerForManagedKey(codeSigningTenantA, "pkcs11", created.KeyID, crypto.RSA2048, created.PublicDER, signing.PurposeCodeSign, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "release signer (SoftHSM)", RequestedEKUs: []string{"codeSigning"}}, signer)
	if err != nil || crypto.VerifyCertificateRequest(csr) != nil {
		t.Fatalf("a certificate request signed in SoftHSM: %v", err)
	}

	svc, err := codesign.New(codesign.Config{TenantID: codeSigningTenantA, Keys: codeSigningKeys{"release-hsm": signer}})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := crypto.Digest(crypto.SHA256, []byte("an artifact signed inside SoftHSM"))
	if err != nil {
		t.Fatal(err)
	}
	request := codesign.SignRequest{OperationID: "p9-codesign-op-1", Principal: "release-bot", KeyID: "release-hsm", ArtifactType: "pkcs11:CKM_SHA256_RSA_PKCS", Digest: digest}
	first, err := svc.Sign(ctx, request)
	if err != nil {
		t.Fatalf("sign in SoftHSM: %v", err)
	}
	if err := svc.Verify(first, digest); err != nil || !bytes.Equal(first.PublicKeyDER, created.PublicDER) {
		t.Fatalf("the SoftHSM signature does not verify against the key: %v", err)
	}
	again, err := svc.Sign(ctx, request)
	if err != nil || !bytes.Equal(again.Value, first.Value) {
		t.Fatalf("the same command signed twice: %v", err)
	}
	other := bytes.Clone(digest)
	other[0] ^= 0x01
	if _, err := svc.Sign(ctx, codesign.SignRequest{OperationID: "p9-codesign-op-1", Principal: "release-bot", KeyID: "release-hsm", ArtifactType: "pkcs11:CKM_SHA256_RSA_PKCS", Digest: other}); err == nil {
		t.Fatal("the command signed another digest")
	}
	foreign, err := client.SignerForManagedKey(codeSigningTenantB, "pkcs11", created.KeyID, crypto.RSA2048, created.PublicDER, signing.PurposeCodeSign, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreign.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256, RSAPadding: crypto.RSAPKCS1v15}); err == nil {
		t.Fatal("another tenant signed with the SoftHSM code-signing key")
	}
	t.Log("SOFTHSM_CODE_SIGNING_OK")

	// P9-L3: an EC managed key in the same token. Its public key is the
	// token's own, and a certificate request it signs inside SoftHSM
	// verifies.
	ecKey, err := client.ManageKey(ctx, signing.ManagedKeyCommand{
		TenantID: codeSigningTenantA, Provider: "pkcs11", OperationID: "p9l3-generate-ec-code-signing-key",
		Action: signing.ManagedKeyGenerate, Algorithm: crypto.ECDSAP256,
	})
	if err != nil || ecKey.KeyID == "" || ecKey.Algorithm != crypto.ECDSAP256 || len(ecKey.PublicDER) == 0 {
		t.Fatalf("the EC code-signing key in SoftHSM = %+v, %v", ecKey, err)
	}
	ecSigner, err := client.SignerForManagedKey(codeSigningTenantA, "pkcs11", ecKey.KeyID, crypto.ECDSAP256, ecKey.PublicDER, signing.PurposeCodeSign, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	ecCSR, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "release signer EC (SoftHSM)", RequestedEKUs: []string{"codeSigning"}}, ecSigner)
	if err != nil || crypto.VerifyCertificateRequest(ecCSR) != nil {
		t.Fatalf("a certificate request signed by the EC key in SoftHSM: %v", err)
	}
	t.Log("SOFTHSM_EC_MANAGED_KEY_OK")
}
