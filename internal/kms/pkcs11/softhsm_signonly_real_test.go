// SPDX-License-Identifier: BUSL-1.1

//go:build pkcs11cgo && cgo

package pkcs11_test

import (
	"os"
	"strings"
	"testing"

	p11 "github.com/miekg/pkcs11"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/kms/pkcs11"
)

// P9-L4: a key pair the managed-key provider generates in the HSM can only
// sign and verify. The template used to leave the token's defaults, and SoftHSM
// made the private key usable to decrypt and unwrap and the public key to
// encrypt and wrap — uses a signing key must never have.
func TestSoftHSMGeneratedKeysAreSignOnlyP9L4(t *testing.T) {
	modulePath := os.Getenv("TRSTCTL_SOFTHSM_MODULE")
	tokenLabel := os.Getenv("TRSTCTL_SOFTHSM_TOKEN_LABEL")
	userPIN := os.Getenv("TRSTCTL_SOFTHSM_USER_PIN")
	if modulePath == "" || tokenLabel == "" || userPIN == "" {
		t.Skip("TRSTCTL_SOFTHSM_MODULE, TRSTCTL_SOFTHSM_TOKEN_LABEL, and TRSTCTL_SOFTHSM_USER_PIN are required")
	}
	const prefix = "trstctl-p9l4"
	sess, err := pkcs11.OpenModuleSession(pkcs11.ModuleConfig{
		ModulePath: modulePath, TokenLabel: tokenLabel, UserPIN: []byte(userPIN), KeyLabelPrefix: prefix,
	})
	if err != nil {
		t.Fatalf("open SoftHSM module session: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	if _, err := pkcs11.New(sess).GenerateKey(crypto.RSA2048); err != nil {
		t.Fatalf("generate a managed key in SoftHSM: %v", err)
	}

	ctx := p11.New(modulePath)
	if ctx == nil {
		t.Fatal("load the PKCS #11 module")
	}
	if err := ctx.Initialize(); err != nil && !strings.Contains(err.Error(), "CKR_CRYPTOKI_ALREADY_INITIALIZED") {
		t.Fatal(err)
	}
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		t.Fatal(err)
	}
	var session p11.SessionHandle
	for _, slot := range slots {
		info, err := ctx.GetTokenInfo(slot)
		if err != nil || strings.TrimSpace(info.Label) != tokenLabel {
			continue
		}
		if session, err = ctx.OpenSession(slot, p11.CKF_SERIAL_SESSION); err != nil {
			t.Fatal(err)
		}
		if err := ctx.Login(session, p11.CKU_USER, userPIN); err != nil && !strings.Contains(err.Error(), "CKR_USER_ALREADY_LOGGED_IN") {
			t.Fatal(err)
		}
		break
	}
	if session == 0 {
		t.Fatalf("token %q not found", tokenLabel)
	}
	t.Cleanup(func() { _ = ctx.CloseSession(session) })
	flag := func(attrs []*p11.Attribute, kind uint) (bool, bool) {
		for _, a := range attrs {
			if a.Type == kind {
				return len(a.Value) > 0 && a.Value[0] != 0, true
			}
		}
		return false, false
	}
	checked := map[uint]int{}
	for class, want := range map[uint]map[uint]bool{
		p11.CKO_PRIVATE_KEY: {p11.CKA_SIGN: true, p11.CKA_DECRYPT: false, p11.CKA_UNWRAP: false},
		p11.CKO_PUBLIC_KEY:  {p11.CKA_VERIFY: true, p11.CKA_ENCRYPT: false, p11.CKA_WRAP: false},
	} {
		if err := ctx.FindObjectsInit(session, []*p11.Attribute{p11.NewAttribute(p11.CKA_CLASS, class)}); err != nil {
			t.Fatal(err)
		}
		objects, _, err := ctx.FindObjects(session, 64)
		_ = ctx.FindObjectsFinal(session)
		if err != nil {
			t.Fatal(err)
		}
		for _, object := range objects {
			labels, err := ctx.GetAttributeValue(session, object, []*p11.Attribute{p11.NewAttribute(p11.CKA_LABEL, nil)})
			if err != nil || len(labels) != 1 || !strings.HasPrefix(string(labels[0].Value), prefix+"-") {
				continue
			}
			query := make([]*p11.Attribute, 0, len(want))
			for kind := range want {
				query = append(query, p11.NewAttribute(kind, nil))
			}
			attrs, err := ctx.GetAttributeValue(session, object, query)
			if err != nil {
				t.Fatal(err)
			}
			for kind, expected := range want {
				if got, ok := flag(attrs, kind); !ok || got != expected {
					t.Fatalf("%s (class %d) attribute 0x%x = %v (present %v), want %v", labels[0].Value, class, kind, got, ok, expected)
				}
			}
			checked[class]++
		}
	}
	if checked[p11.CKO_PRIVATE_KEY] == 0 || checked[p11.CKO_PUBLIC_KEY] == 0 {
		t.Fatalf("checked %v; want the generated pair's private and public objects", checked)
	}
	t.Log("SOFTHSM_SIGN_ONLY_OK")
}
