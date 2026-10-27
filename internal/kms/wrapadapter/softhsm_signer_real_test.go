// SPDX-License-Identifier: BUSL-1.1

//go:build pkcs11cgo && cgo

package wrapadapter_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/kmswrap"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/kms/pkcs11"
	"trstctl.com/trstctl/internal/kms/wrapadapter"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// A200 against SoftHSM: the signer key store seals the issuing CA key through
// the cgo adapter under a non-extractable token AES key. The token opens the
// wrapped data key under the key store's purpose; a restarted signer signs
// with the same CA key; once the AES key is deleted from the token, the key
// store no longer opens.
func TestSoftHSMSealsTheSignerCAKeyThroughTheAdapter(t *testing.T) {
	module := os.Getenv("TRSTCTL_SOFTHSM_MODULE")
	token := os.Getenv("TRSTCTL_SOFTHSM_TOKEN_LABEL")
	pin := os.Getenv("TRSTCTL_SOFTHSM_USER_PIN")
	adapter := os.Getenv("TRSTCTL_KMS_WRAP_ADAPTER")
	if module == "" || token == "" || pin == "" || adapter == "" {
		t.Skip("TRSTCTL_SOFTHSM_MODULE, TRSTCTL_SOFTHSM_TOKEN_LABEL, TRSTCTL_SOFTHSM_USER_PIN and TRSTCTL_KMS_WRAP_ADAPTER are required")
	}
	const keyLabel = "trstctl-signer-keystore"
	ctx := context.Background()
	dir := t.TempDir()
	pinFile := filepath.Join(dir, "pin")
	if err := os.WriteFile(pinFile, []byte(pin+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(map[string]any{"pkcs11": map[string]any{
		"module_path": module, "token_label": token, "user_pin_file": pinFile,
	}})
	if err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(dir, "kms-wrap.json")
	if err := os.WriteFile(configFile, config, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(wrapadapter.ConfigEnv, configFile)
	wrapper, err := kmswrap.NewExternalKMSWrapper(kmswrap.ExternalKMSConfig{
		Provider: "pkcs11", KeyRef: keyLabel, WrapCommand: adapter, Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	keystore := filepath.Join(dir, "keystore")
	first, err := signing.NewPersistentServer(signing.NewKeyStore(keystore, wrapper))
	if err != nil {
		t.Fatal(err)
	}
	gen, err := first.GenerateKey(ctx, &signerpb.GenerateKeyRequest{
		Algorithm: signerpb.Algorithm_ALGORITHM_ECDSA_P256, RequestedId: "issuing-ca",
	})
	if err != nil {
		t.Fatalf("generate the issuing CA key: %v", err)
	}

	sealed, err := os.ReadFile(filepath.Join(keystore, "issuing-ca.key")) // #nosec G304 -- the test's own key store (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, _, err := seal.ContainerWrappedDEK(sealed)
	if err != nil || !bytes.HasPrefix(wrapped, []byte("TKW1P\x00\x00")) {
		t.Fatalf("the CA key's wrapped data key = %q, %v; want a PKCS#11 adapter frame", wrapped, err)
	}
	// The token itself opens the data key under the key store's purpose.
	session, err := pkcs11.OpenModuleSession(pkcs11.ModuleConfig{ModulePath: module, TokenLabel: token, UserPIN: []byte(pin)})
	if err != nil {
		t.Fatal(err)
	}
	dataKey, err := session.(pkcs11.SecretKeySession).OpenWithKey(keyLabel, wrapped[7:], []byte(wrapadapter.Purpose))
	_ = session.Close()
	if err != nil || len(dataKey) != 32 || bytes.Contains(sealed, dataKey) {
		t.Fatalf("the token's own open of the wrapped data key: %v", err)
	}
	clear(dataKey)

	signWith := func(server *signing.Server) ([]byte, error) {
		pub, err := server.GetPublicKey(ctx, &signerpb.GetPublicKeyRequest{Handle: &signerpb.KeyHandle{Id: "issuing-ca"}})
		if err != nil {
			return nil, err
		}
		if _, err := server.Sign(ctx, &signerpb.SignRequest{
			Handle: &signerpb.KeyHandle{Id: "issuing-ca"}, Digest: make([]byte, 32), Hash: signerpb.Hash_HASH_SHA256,
		}); err != nil {
			return nil, err
		}
		return pub.GetPublicKey(), nil
	}
	second, err := signing.NewPersistentServer(signing.NewKeyStore(keystore, wrapper))
	if err != nil {
		t.Fatalf("restart over the HSM-wrapped key store: %v", err)
	}
	if pub, err := signWith(second); err != nil || !bytes.Equal(pub, gen.GetPublicKey()) {
		t.Fatalf("the restarted signer's CA key: %v", err)
	}

	del := exec.Command("pkcs11-tool", "--module", module, "--token-label", token, "--login", "--pin", pin, // #nosec G204 -- fixed SoftHSM tool inside the test container (CWE-78)
		"--delete-object", "--type", "secrkey", "--label", keyLabel)
	if out, err := del.CombinedOutput(); err != nil {
		t.Fatalf("delete the token AES key: %v\n%s", err, out)
	}
	third, err := signing.NewPersistentServer(signing.NewKeyStore(keystore, wrapper))
	if err == nil {
		if _, err = signWith(third); err == nil {
			t.Fatal("the CA key opened after its token AES key was deleted")
		}
	}
	t.Logf("SOFTHSM_SIGNER_KEYSTORE_OK refused-after-delete=%q", err)
}
