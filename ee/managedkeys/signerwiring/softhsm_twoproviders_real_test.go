// SPDX-License-Identifier: LicenseRef-trstctl-EE

//go:build pkcs11cgo && cgo

package signerwiring_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/managedkeys/signerwiring"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

const (
	twoProviderTenantA = "11111111-1111-4111-8111-111111111111"
	twoProviderTenantB = "22222222-2222-4222-8222-222222222222"
)

// A199 against SoftHSM and the KMS emulator: one signer holds a PKCS#11 HSM
// and AWS KMS at once. Tenant A's key is created in the HSM and tenant B's in
// KMS; each result names its provider, each provider proves custody with a
// fresh challenge signature, and neither provider nor tenant can reach the
// other's key.
func TestSoftHSMAndKMSEmulatorInOneSigner(t *testing.T) {
	modulePath := os.Getenv("TRSTCTL_SOFTHSM_MODULE")
	tokenLabel := os.Getenv("TRSTCTL_SOFTHSM_TOKEN_LABEL")
	userPIN := os.Getenv("TRSTCTL_SOFTHSM_USER_PIN")
	emulator := os.Getenv("TRSTCTL_KMS_EMULATOR_ENDPOINT")
	if modulePath == "" || tokenLabel == "" || userPIN == "" || emulator == "" {
		t.Skip("TRSTCTL_SOFTHSM_MODULE, TRSTCTL_SOFTHSM_TOKEN_LABEL, TRSTCTL_SOFTHSM_USER_PIN and TRSTCTL_KMS_EMULATOR_ENDPOINT are required")
	}
	dir := t.TempDir()
	pinFile := filepath.Join(dir, "pkcs11-pin")
	awsKeyFile := filepath.Join(dir, "aws-secret")
	for path, value := range map[string]string{pinFile: userPIN + "\n", awsKeyFile: "dod-aws-managed-key-secret-material"} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	config := filepath.Join(dir, "managed-keys.json")
	body := `{"enabled":true,"provider":"pkcs11","providers":["pkcs11","aws"],` +
		`"pkcs11":{"module_path":"` + modulePath + `","token_label":"` + tokenLabel + `","user_pin_file":"` + pinFile + `","key_label_prefix":"trstctl-a199"},` +
		`"aws":{"region":"us-east-1","endpoint":"` + emulator + `","allow_insecure_loopback":true,"access_key_id":"AKIADODMANAGEDKEY",` +
		`"secret_access_key_file":"` + awsKeyFile + `","private_egress_cidrs":["127.0.0.0/8"]}}`
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	option, err := signerwiring.ProviderOption(config, filepath.Join(dir, "journal"))
	if err != nil {
		t.Fatalf("a signer holding the HSM and KMS: %v", err)
	}
	socket := filepath.Join(dir, "signer.sock")
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		served <- signing.ServeServerWithOptions(ctx, socket, signing.NewServer(option), signing.ServeOptions{})
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

	manage := func(tenantID, provider, operationID string, action signing.ManagedKeyAction, keyID string) (signing.ManagedKeyResult, error) {
		return client.ManageKey(ctx, signing.ManagedKeyCommand{
			TenantID: tenantID, Provider: provider, OperationID: operationID,
			Action: action, KeyID: keyID, Algorithm: crypto.RSA2048,
		})
	}
	hsmKey, err := manage(twoProviderTenantA, "pkcs11", "a199-generate-a", signing.ManagedKeyGenerate, "")
	if err != nil || hsmKey.Provider != "pkcs11" || hsmKey.KeyID == "" || len(hsmKey.PublicDER) == 0 {
		t.Fatalf("tenant A's key in the HSM = %+v, %v", hsmKey, err)
	}
	kmsKey, err := manage(twoProviderTenantB, "aws", "a199-generate-b", signing.ManagedKeyGenerate, "")
	if err != nil || kmsKey.Provider != "aws-kms" || kmsKey.KeyID == "" || len(kmsKey.PublicDER) == 0 {
		t.Fatalf("tenant B's key in KMS = %+v, %v", kmsKey, err)
	}
	if hsmKey.KeyID == kmsKey.KeyID {
		t.Fatal("the two providers returned the same key handle")
	}
	for _, c := range []struct {
		tenantID, provider, operationID string
		key                             signing.ManagedKeyResult
	}{
		{twoProviderTenantA, "pkcs11", "a199-verify-a", hsmKey},
		{twoProviderTenantB, "aws", "a199-verify-b", kmsKey},
	} {
		verified, err := manage(c.tenantID, c.provider, c.operationID, signing.ManagedKeyVerifyCustody, c.key.KeyID)
		if err != nil || verified.KeyID != c.key.KeyID || verified.Provider != c.key.Provider {
			t.Fatalf("%s custody proof = %+v, %v", c.key.Provider, verified, err)
		}
	}
	if _, err := manage(twoProviderTenantA, "aws", "a199-cross-provider", signing.ManagedKeyVerifyCustody, hsmKey.KeyID); err == nil {
		t.Fatal("KMS answered for a key the HSM holds")
	}
	if _, err := manage(twoProviderTenantB, "pkcs11", "a199-cross-tenant", signing.ManagedKeyVerifyCustody, hsmKey.KeyID); err == nil {
		t.Fatal("tenant B reached tenant A's HSM key")
	}
	t.Log("SOFTHSM_KMS_TWO_PROVIDERS_OK")
}
