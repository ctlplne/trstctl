// SPDX-License-Identifier: LicenseRef-trstctl-EE

package delegation

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

func TestDurableAttestationTrustStore_VerifiesSignedEvidence(t *testing.T) {
	signer, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	store := NewDurableAttestationTrustStore(t.TempDir())
	if err := store.PutVerifier(context.Background(), "attestor-1", signer.Public().DER); err != nil {
		t.Fatalf("PutVerifier: %v", err)
	}
	payload, err := SignAttestation(signer, "attestor-1", "software", "agent-1",
		map[string]string{"attestation_class": "software"}, []byte("nonce-1"))
	if err != nil {
		t.Fatalf("SignAttestation: %v", err)
	}
	got, err := store.VerifyEvidence("software", payload)
	if err != nil {
		t.Fatalf("VerifyEvidence: %v", err)
	}
	if got.Subject != "agent-1" || got.Claims["attestation_class"] != "software" {
		t.Fatalf("verified attestation = %+v", got)
	}
	if _, err := store.VerifyEvidence("software", payload); !errors.Is(err, ErrAttestationReplay) {
		t.Fatalf("VerifyEvidence(replay) = %v, want ErrAttestationReplay", err)
	}
	if _, err := store.VerifyEvidence("tpm", payload); !errors.Is(err, ErrAttestationInvalid) {
		t.Fatalf("VerifyEvidence(method mismatch) = %v, want ErrAttestationInvalid", err)
	}
}
