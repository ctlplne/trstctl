// SPDX-License-Identifier: BUSL-1.1

//go:build pkcs11cgo && cgo

package pkcs11

import (
	"context"
	"os"
	"testing"
	"time"

	p11 "github.com/miekg/pkcs11"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/crypto/deviceattesttest"
)

// A175 against a real PKCS#11 module: SoftHSM generates the edge key, a
// stand-in vendor hierarchy attests it, and the attestation is stored on the
// token as certificate objects under the labels a YubiKey's PIV module uses.
// The agent's read of those objects returns the chain leaf first, and it
// verifies to the pinned stand-in root over the CSR's key. SoftHSM has no
// attestation of its own: this proves the read and the verification, not a
// vendor's hardware.
func TestSoftHSMTokenAttestationObjectsRead(t *testing.T) {
	modulePath := os.Getenv("TRSTCTL_SOFTHSM_MODULE")
	tokenLabel := os.Getenv("TRSTCTL_SOFTHSM_TOKEN_LABEL")
	userPIN := os.Getenv("TRSTCTL_SOFTHSM_USER_PIN")
	if modulePath == "" || tokenLabel == "" || userPIN == "" {
		t.Skip("TRSTCTL_SOFTHSM_MODULE, TRSTCTL_SOFTHSM_TOKEN_LABEL, and TRSTCTL_SOFTHSM_USER_PIN are required")
	}
	sess, err := OpenModuleSession(ModuleConfig{ModulePath: modulePath, TokenLabel: tokenLabel, UserPIN: []byte(userPIN), KeyLabelPrefix: "trstctl-edge-a175"})
	if err != nil {
		t.Fatalf("open SoftHSM session: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	_, csrDER, err := crypto.GenerateEdgeCAKeyHandleAndCSR(context.Background(), "a175-softhsm-token-attestation", "softhsm token edge CA", crypto.RSA2048, New(sess))
	if err != nil {
		t.Fatalf("generate the edge key on the token: %v", err)
	}
	now := time.Now().UTC()
	vendor, err := deviceattesttest.NewTokenAttestationAuthority(now, 17500175)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := vendor.AttestCSR(csrDER, now)
	if err != nil {
		t.Fatal(err)
	}
	const leafLabel, deviceLabel = "X.509 Certificate for PIV Attestation 9c", "X.509 Certificate for PIV Attestation"
	module := sess.(*moduleSession)
	for _, object := range []struct {
		label string
		der   []byte
	}{{leafLabel, chain[0]}, {deviceLabel, chain[1]}} {
		subject, err := deviceattesttest.CertificateSubjectDER(object.der)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := module.ctx.CreateObject(module.session, []*p11.Attribute{
			p11.NewAttribute(p11.CKA_CLASS, p11.CKO_CERTIFICATE),
			p11.NewAttribute(p11.CKA_CERTIFICATE_TYPE, p11.CKC_X_509),
			p11.NewAttribute(p11.CKA_TOKEN, true),
			p11.NewAttribute(p11.CKA_LABEL, object.label),
			p11.NewAttribute(p11.CKA_SUBJECT, subject),
			p11.NewAttribute(p11.CKA_VALUE, object.der),
		}); err != nil {
			t.Fatalf("store %q on the token: %v", object.label, err)
		}
	}

	read, err := module.CertificatesByLabel(leafLabel, deviceLabel)
	if err != nil {
		t.Fatalf("read the attestation objects: %v", err)
	}
	if err := deviceattest.TokenAttestationCertifiesCSR(read[0], csrDER); err != nil {
		t.Fatal(err)
	}
	attested, err := deviceattest.VerifyPKCS11TokenAttestation(read, [][]byte{vendor.RootPEM()}, csrDER, now)
	if err != nil || attested.Serial != "17500175" {
		t.Fatalf("verify the token's chain = %+v, %v", attested, err)
	}
	if _, err := module.CertificatesByLabel("X.509 Certificate for PIV Attestation 9a"); err == nil {
		t.Fatal("a label the token does not hold was read")
	}
	t.Log("SOFTHSM_TOKEN_ATTESTATION_OK")
}
