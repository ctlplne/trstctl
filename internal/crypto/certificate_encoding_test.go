// SPDX-License-Identifier: MPL-2.0

package crypto_test

import (
	"bytes"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func TestNormalizeCertificateDERAcceptsOnePEMOrDERAndRejectsAmbiguityAUD53(t *testing.T) {
	t.Parallel()
	// The trailing 0x20 is intentional. DER is binary and must not be trimmed
	// merely because its final signature byte happens to look like ASCII space.
	der := []byte{0x30, 0x04, 0x02, 0x02, 0x01, 0x20}

	for name, raw := range map[string][]byte{
		"der": der,
		"pem": crypto.EncodeCertificatePEM(der),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := crypto.NormalizeCertificateDER(raw)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, der) {
				t.Fatalf("normalized = %x, want %x", got, der)
			}
		})
	}

	if _, err := crypto.NormalizeCertificateDER(append(crypto.EncodeCertificatePEM(der), crypto.EncodeCertificatePEM(der)...)); err == nil {
		t.Fatal("multiple PEM certificate blocks were accepted as one trust root")
	}
	if _, err := crypto.NormalizeCertificateDER([]byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n")); err == nil {
		t.Fatal("a private-key PEM block was accepted as a certificate")
	}
}
