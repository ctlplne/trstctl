// SPDX-License-Identifier: BUSL-1.1

//go:build cgo

package pkcs11_test

import (
	"os"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/kms/pkcs11"
)

// P9-L3: SoftHSM generates P-256 and P-384 keys inside the token, sign-only
// and never extractable; each signs a digest with CKM_ECDSA and the ASN.1
// signature verifies against the public key the token returned. The signer
// wire's default padding is ignored and PSS refused for an EC key, and an
// operation's key object, once EC, is not taken for an RSA request.
func TestSoftHSMGeneratesECKeysP9L3(t *testing.T) {
	modulePath := os.Getenv("TRSTCTL_SOFTHSM_MODULE")
	tokenLabel := os.Getenv("TRSTCTL_SOFTHSM_TOKEN_LABEL")
	userPIN := os.Getenv("TRSTCTL_SOFTHSM_USER_PIN")
	if modulePath == "" || tokenLabel == "" || userPIN == "" {
		t.Skip("TRSTCTL_SOFTHSM_MODULE, TRSTCTL_SOFTHSM_TOKEN_LABEL, and TRSTCTL_SOFTHSM_USER_PIN are required")
	}
	sess, err := pkcs11.OpenModuleSession(pkcs11.ModuleConfig{
		ModulePath: modulePath, TokenLabel: tokenLabel, UserPIN: []byte(userPIN), KeyLabelPrefix: "trstctl-p9l3",
	})
	if err != nil {
		t.Fatalf("open SoftHSM module session: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	backend := pkcs11.New(sess)
	for alg, hash := range map[crypto.Algorithm]crypto.Hash{crypto.ECDSAP256: crypto.SHA256, crypto.ECDSAP384: crypto.SHA384} {
		signer, err := backend.GenerateKey(alg)
		if err != nil {
			t.Fatalf("generate %s in SoftHSM: %v", alg, err)
		}
		message := []byte("an artifact signed by a " + string(alg) + " key inside SoftHSM")
		sig, err := signer.Sign(message, crypto.SignOptions{Hash: hash})
		if err != nil {
			t.Fatalf("sign with %s: %v", alg, err)
		}
		if err := crypto.Verify(signer.Public(), message, sig, crypto.SignOptions{Hash: hash}); err != nil {
			t.Fatalf("the %s signature does not verify: %v", alg, err)
		}
		// The signer's wire default (PKCS #1 v1.5) is ignored; PSS is refused.
		if sig, err := signer.Sign(message, crypto.SignOptions{Hash: hash, RSAPadding: crypto.RSAPKCS1v15}); err != nil ||
			crypto.Verify(signer.Public(), message, sig, crypto.SignOptions{Hash: hash}) != nil {
			t.Fatalf("%s under the wire's default padding: %v", alg, err)
		}
		if _, err := signer.Sign(message, crypto.SignOptions{Hash: hash, RSAPadding: crypto.RSAPSS}); err == nil ||
			!strings.Contains(err.Error(), "no RSA padding") {
			t.Fatalf("%s took PSS: %v", alg, err)
		}
	}
	ops, ok := sess.(pkcs11.OperationSession)
	if !ok {
		t.Fatal("the module session does not key objects by operation")
	}
	handle, der, err := ops.GenerateKeyForOperation("p9l3-op-ec", crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	again, againDER, err := ops.GenerateKeyForOperation("p9l3-op-ec", crypto.ECDSAP256)
	if err != nil || again != handle || string(againDER) != string(der) {
		t.Fatalf("the operation's EC key was not reused: %v", err)
	}
	if _, _, err := ops.GenerateKeyForOperation("p9l3-op-ec", crypto.RSA2048); err == nil || !strings.Contains(err.Error(), "holds a ECDSA-P256 key") {
		t.Fatalf("an RSA request took the operation's EC key: %v", err)
	}
	t.Log("SOFTHSM_EC_OK")
}
