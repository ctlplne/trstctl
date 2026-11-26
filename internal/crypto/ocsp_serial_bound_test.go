// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/x509"
	"errors"
	"math/big"
	"testing"

	"golang.org/x/crypto/ocsp"
)

func TestOCSPRequestRejectsSerialOutsideCertificateBoundary(t *testing.T) {
	issuerDER, _ := caForRevocation(t)
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	for name, serial := range map[string]*big.Int{
		"zero":           big.NewInt(0),
		"negative":       big.NewInt(-1),
		"21 octet DER":   new(big.Int).Lsh(big.NewInt(1), 159),
		"over 20 octets": new(big.Int).Lsh(big.NewInt(1), 160),
	} {
		t.Run(name, func(t *testing.T) {
			reqDER, err := ocsp.CreateRequest(&x509.Certificate{SerialNumber: serial}, issuer, nil)
			if err != nil {
				t.Fatalf("build parseable boundary request: %v", err)
			}
			if _, err := ParseOCSPRequestSerial(reqDER); !errors.Is(err, ErrMalformedOCSPRequest) {
				t.Fatalf("public responder accepted serial %s: %v", serial, err)
			}
			if _, err := ValidateOCSPRequestForIssuer(reqDER, issuerDER); !errors.Is(err, ErrMalformedOCSPRequest) {
				t.Fatalf("relay cache accepted serial %s: %v", serial, err)
			}
		})
	}
	maximum := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 159), big.NewInt(1))
	reqDER, err := ocsp.CreateRequest(&x509.Certificate{SerialNumber: maximum}, issuer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseOCSPRequestSerial(reqDER); err != nil {
		t.Fatalf("maximum 20-octet DER serial rejected: %v", err)
	}
	if _, err := ValidateOCSPRequestForIssuer(reqDER, issuerDER); err != nil {
		t.Fatalf("maximum issuer-bound serial rejected: %v", err)
	}
}
