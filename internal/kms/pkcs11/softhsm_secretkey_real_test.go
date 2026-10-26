// SPDX-License-Identifier: BUSL-1.1

//go:build pkcs11cgo && cgo

package pkcs11_test

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/kms/pkcs11"
)

// The container harness provisions these with pkcs11-tool, as an operator
// would: one sensitive, never-extractable AES-256 key, one extractable, one
// AES-128.
const (
	softHSMTenantKEKLabel   = "trstctl-tenant-kek-a"
	softHSMExtractableLabel = "trstctl-tenant-kek-extractable"
	softHSMAES128Label      = "trstctl-tenant-kek-aes128"
)

func openSoftHSMSecretKeySession(t *testing.T) (pkcs11.Session, pkcs11.SecretKeySession) {
	t.Helper()
	modulePath := os.Getenv("TRSTCTL_SOFTHSM_MODULE")
	tokenLabel := os.Getenv("TRSTCTL_SOFTHSM_TOKEN_LABEL")
	userPIN := os.Getenv("TRSTCTL_SOFTHSM_USER_PIN")
	if modulePath == "" || tokenLabel == "" || userPIN == "" || os.Getenv("TRSTCTL_SOFTHSM_AES_KEYS") != "1" {
		t.Skip("TRSTCTL_SOFTHSM_MODULE, TRSTCTL_SOFTHSM_TOKEN_LABEL, TRSTCTL_SOFTHSM_USER_PIN and provisioned AES keys are required")
	}
	sess, err := pkcs11.OpenModuleSession(pkcs11.ModuleConfig{
		ModulePath: modulePath, TokenLabel: tokenLabel, UserPIN: []byte(userPIN), KeyLabelPrefix: "trstctl-a123",
	})
	if err != nil {
		t.Fatalf("open SoftHSM module session: %v", err)
	}
	keys, ok := sess.(pkcs11.SecretKeySession)
	if !ok {
		_ = sess.Close()
		t.Fatal("the module session does not seal under an AES key")
	}
	return sess, keys
}

// A123: a value sealed under the operator's AES key opens only with the same
// key and associated data, a changed byte or binding does not authenticate,
// each seal draws a fresh IV, and keys that are missing, extractable or not
// AES-256 are refused before any encryption.
func TestSoftHSMSealsAndOpensUnderAnAESKey(t *testing.T) {
	sess, keys := openSoftHSMSecretKeySession(t)
	t.Cleanup(func() { _ = sess.Close() })

	plain, err := crypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("tenant=a;domain=d;generation=1")
	sealed, err := keys.SealWithKey(softHSMTenantKEKLabel, plain, aad)
	if err != nil {
		t.Fatalf("seal under the AES key: %v", err)
	}
	if len(sealed) != 12+len(plain)+16 || bytes.Contains(sealed, plain) {
		t.Fatalf("sealed value is %d bytes or carries the plaintext", len(sealed))
	}
	again, err := keys.SealWithKey(softHSMTenantKEKLabel, plain, aad)
	if err != nil || bytes.Equal(again[:12], sealed[:12]) {
		t.Fatalf("a second seal reused the IV or failed: %v", err)
	}
	opened, err := keys.OpenWithKey(softHSMTenantKEKLabel, sealed, aad)
	if err != nil || !bytes.Equal(opened, plain) {
		t.Fatalf("open = %v, want the sealed value back", err)
	}
	if _, err := keys.OpenWithKey(softHSMTenantKEKLabel, sealed, []byte("tenant=b;domain=d;generation=1")); !errors.Is(err, pkcs11.ErrSealedValueInvalid) {
		t.Fatalf("open under another binding = %v, want ErrSealedValueInvalid", err)
	}
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := keys.OpenWithKey(softHSMTenantKEKLabel, tampered, aad); !errors.Is(err, pkcs11.ErrSealedValueInvalid) {
		t.Fatalf("open of a changed value = %v, want ErrSealedValueInvalid", err)
	}
	if _, err := keys.SealWithKey("trstctl-no-such-key", plain, aad); !errors.Is(err, pkcs11.ErrSecretKeyNotFound) {
		t.Fatalf("seal under a missing label = %v, want ErrSecretKeyNotFound", err)
	}
	for _, label := range []string{softHSMExtractableLabel, softHSMAES128Label} {
		if _, err := keys.SealWithKey(label, plain, aad); !errors.Is(err, pkcs11.ErrSecretKeyPolicy) {
			t.Fatalf("seal under %s = %v, want ErrSecretKeyPolicy", label, err)
		}
	}
	t.Log("SOFTHSM_AES_GCM_OK")
}

// PKCS#11 initializes a module once per process and holds a token's login for
// the whole process. A second session on the module (managed keys and tenant
// KEK custody in one signer) shares the first one's context, and closing either
// leaves the other working.
func TestSoftHSMSecondSessionSharesTheModule(t *testing.T) {
	first, firstKeys := openSoftHSMSecretKeySession(t)
	second, secondKeys := openSoftHSMSecretKeySession(t)
	t.Cleanup(func() { _ = second.Close() })

	aad := []byte("shared-module")
	sealed, err := firstKeys.SealWithKey(softHSMTenantKEKLabel, []byte("domain kek bytes"), aad)
	if err != nil {
		t.Fatalf("seal on the first session: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close the first session: %v", err)
	}
	if _, err := firstKeys.OpenWithKey(softHSMTenantKEKLabel, sealed, aad); err == nil {
		t.Fatal("a closed session still opened a value")
	}
	opened, err := secondKeys.OpenWithKey(softHSMTenantKEKLabel, sealed, aad)
	if err != nil || string(opened) != "domain kek bytes" {
		t.Fatalf("the second session after the first closed = %q, %v", opened, err)
	}
	if err := crypto.ConformBackend(pkcs11.New(second), []crypto.Algorithm{crypto.RSA2048}); err != nil {
		t.Fatalf("the second session cannot sign after the first closed: %v", err)
	}
	third, thirdKeys := openSoftHSMSecretKeySession(t)
	defer func() { _ = third.Close() }()
	if _, err := thirdKeys.OpenWithKey(softHSMTenantKEKLabel, sealed, aad); err != nil {
		t.Fatalf("a session opened while another is live: %v", err)
	}
	t.Log("SOFTHSM_SHARED_MODULE_OK")
}
