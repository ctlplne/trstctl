// SPDX-License-Identifier: MPL-2.0

//go:build pkcs11cgo && cgo

package pkcs11_test

import (
	"os"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/kms/pkcs11"
)

func TestSoftHSMRealBindingGenerateSign(t *testing.T) {
	modulePath := os.Getenv("TRSTCTL_SOFTHSM_MODULE")
	tokenLabel := os.Getenv("TRSTCTL_SOFTHSM_TOKEN_LABEL")
	userPIN := os.Getenv("TRSTCTL_SOFTHSM_USER_PIN")
	if modulePath == "" || tokenLabel == "" || userPIN == "" {
		t.Skip("TRSTCTL_SOFTHSM_MODULE, TRSTCTL_SOFTHSM_TOKEN_LABEL, and TRSTCTL_SOFTHSM_USER_PIN are required")
	}

	sess, err := pkcs11.OpenModuleSession(pkcs11.ModuleConfig{
		ModulePath:     modulePath,
		TokenLabel:     tokenLabel,
		UserPIN:        []byte(userPIN),
		KeyLabelPrefix: "trstctl-kms03",
	})
	if err != nil {
		t.Fatalf("open SoftHSM module session: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	b := pkcs11.New(sess)
	if err := crypto.ConformBackend(b, []crypto.Algorithm{crypto.RSA2048}); err != nil {
		t.Fatalf("SoftHSM PKCS#11 backend failed conformance: %v", err)
	}
	t.Log("SOFTHSM_PKCS11_OK")
}
