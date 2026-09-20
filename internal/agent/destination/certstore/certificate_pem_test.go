// SPDX-License-Identifier: BUSL-1.1

package certstore

import (
	"bytes"
	"encoding/pem"
	"testing"
)

func TestCertificateDERRejectsEmptyAndWrongBlocks(t *testing.T) {
	for _, input := range [][]byte{
		nil,
		[]byte("not PEM"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE"}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1, 2, 3}}),
	} {
		if der, err := certificateDER(input); err == nil || der != nil {
			t.Fatal("invalid or empty certificate input accepted")
		}
	}
	// DER validation remains the OS's job. This admission check guarantees a
	// nonempty buffer and preserves the exact bytes supplied to that validator.
	want := []byte{0x30, 0x01, 0x00}
	got, err := certificateDER(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: want}))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("nonempty public bytes changed: %x, %v", got, err)
	}
}
