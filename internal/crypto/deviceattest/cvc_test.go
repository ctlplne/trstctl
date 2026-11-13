// SPDX-License-Identifier: BUSL-1.1

package deviceattest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/deviceattesttest"
)

func a175l3CSR(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "edge-ca"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// A175-L3: a SmartCard-HSM's key attestation — an authenticated CV request
// from a device certified by a device issuer CA certified by a pinned CV
// root — verifies for exactly the CSR's key, and names the device serial and
// the root; a forged device, another root, another key, a tampered request
// or expired certificates are refused.
func TestSmartCardHSMKeyAttestationVerifiesTheCSRKeyA175L3(t *testing.T) {
	card, err := deviceattesttest.NewSmartCardHSM("DECC0175")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request, err := card.Attest(key)
	if err != nil {
		t.Fatal(err)
	}
	ev := SmartCardHSMAttestation{AuthenticatedRequest: request, DeviceCVC: card.DeviceCVC, DICACVC: card.DICACVC}
	now := time.Now().UTC()
	roots := [][]byte{card.RootPEM()}
	got, err := VerifySmartCardHSMKeyAttestation(ev, roots, a175l3CSR(t, key), now)
	if err != nil || got.Serial != "DECC0175" || len(got.RootSHA256) != 64 {
		t.Fatalf("attestation = %+v err=%v", got, err)
	}
	if n, err := ParsePinnedCVCertificateRoots(roots); err != nil || n != 1 {
		t.Fatalf("pinned CV roots = %d err=%v", n, err)
	}

	refused := func(name string, ev SmartCardHSMAttestation, roots [][]byte, csr []byte, at time.Time, want string) {
		t.Helper()
		_, err := VerifySmartCardHSMKeyAttestation(ev, roots, csr, at)
		if !errors.Is(err, ErrTokenAttestationRefused) || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s = %v; want a refusal naming %q", name, err, want)
		}
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	refused("another key", ev, roots, a175l3CSR(t, other), now, "different key")
	forged, err := card.AttestWithAnotherDevice(key)
	if err != nil {
		t.Fatal(err)
	}
	refused("a forged device", SmartCardHSMAttestation{AuthenticatedRequest: forged, DeviceCVC: card.DeviceCVC, DICACVC: card.DICACVC},
		roots, a175l3CSR(t, key), now, "device's signature")
	otherCard, err := deviceattesttest.NewSmartCardHSM("DECC0999")
	if err != nil {
		t.Fatal(err)
	}
	refused("another vendor root", ev, [][]byte{otherCard.RootPEM()}, a175l3CSR(t, key), now, "device issuer CA")
	refused("no CV root", ev, nil, a175l3CSR(t, key), now, "pins no CV certificate root")
	refused("the other card's device", SmartCardHSMAttestation{AuthenticatedRequest: request, DeviceCVC: otherCard.DeviceCVC, DICACVC: card.DICACVC},
		roots, a175l3CSR(t, key), now, "device certificate")
	tampered := append([]byte(nil), request...)
	tampered[len(tampered)-70] ^= 0x01
	refused("a tampered request", SmartCardHSMAttestation{AuthenticatedRequest: tampered, DeviceCVC: card.DeviceCVC, DICACVC: card.DICACVC},
		roots, a175l3CSR(t, key), now, "SmartCard-HSM attestation")
	refused("expired certificates", ev, roots, a175l3CSR(t, key), now.AddDate(21, 0, 0), "not valid now")
	refused("not yet valid", ev, roots, a175l3CSR(t, key), now.AddDate(0, 0, -3), "not valid now")
	refused("garbage", SmartCardHSMAttestation{AuthenticatedRequest: []byte{0x67, 0x01, 0x00}, DeviceCVC: card.DeviceCVC, DICACVC: card.DICACVC},
		roots, a175l3CSR(t, key), now, "authenticated")
}

// FuzzParseCVCertificate holds the CV certificate parser to arbitrary bytes:
// it returns an error or a certificate, never panics, and never reads past
// the input.
func FuzzParseCVCertificate(f *testing.F) {
	card, err := deviceattesttest.NewSmartCardHSM("DECC0175")
	if err != nil {
		f.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	request, err := card.Attest(key)
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range [][]byte{card.RootCVC, card.DICACVC, card.DeviceCVC, request, {0x7F, 0x21, 0x00}, {0x67, 0x81}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if c, err := parseCVCertificate(b); err == nil {
			_, _ = c.key.publicKey()
		}
		_, _ = readCVCElements(b)
		_, _ = VerifySmartCardHSMKeyAttestation(SmartCardHSMAttestation{AuthenticatedRequest: b, DeviceCVC: b, DICACVC: b},
			[][]byte{card.RootPEM()}, nil, time.Now())
	})
}
