// SPDX-License-Identifier: BUSL-1.1

package crypto_test

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestUploadableRSAKeypairSignsProofOfPossession(t *testing.T) {
	privateKey, certificate, err := crypto.GenerateUploadableRSAKeypair(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(privateKey)
	if len(certificate) == 0 {
		t.Fatal("empty uploadable certificate")
	}
	signature, err := crypto.SignUploadableRSAKey(privateKey, []byte("trstctl-dod-gcp-auth"))
	if err != nil {
		t.Fatal(err)
	}
	if len(signature) < 128 {
		t.Fatalf("RSA signature length = %d", len(signature))
	}
}
