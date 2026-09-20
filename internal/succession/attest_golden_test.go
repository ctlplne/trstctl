// SPDX-License-Identifier: BUSL-1.1

package succession

import (
	"encoding/hex"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// TestINT11_AttestMessageGolden freezes the signer-attestation message encoding
// (INT-11). The signer attestation is the attribution binding (PCAS-claim-28) and, for v1
// records, the tamper-evidence for RecordType / authz / attestation evidence. Pinning
// its canonical bytes means an accidental format change is caught before it silently
// breaks external verifiers that reproduce the message. The attestation is
// domain-versioned (.../signer-attestation/v1).
func TestINT11_AttestMessageGolden(t *testing.T) {
	rec := SuccessionRecord{
		Fields:                    fixedFields(), // v1 commitment (frozen 86ffbe67...)
		AuthzDigest:               []byte{0x11, 0x22},
		RecordType:                RecRevocation,
		AttestationEvidenceDigest: []byte{0x33, 0x44},
		AttestationType:           "tpm-quote/v1",
	}
	msg, err := attestMessage(rec, "signer-1")
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(crypto.SHA256Sum(msg))
	const want = "46c9e171e79b8f4eb7a2babd90ba2ab23480338fbddc2c2c2e0abdf19a53dea7"
	if want != "GOLDEN" && got != want {
		t.Fatalf("attest-message golden mismatch:\n got %s\nwant %s", got, want)
	}
	t.Logf("ATTEST_MESSAGE_GOLDEN=%s", got)
}

// TestINT11_AuthzDigestGolden freezes the authz-digest encoding (PCAS-claim-42) and pins
// that an empty artifact yields a distinct, well-defined digest.
func TestINT11_AuthzDigestGolden(t *testing.T) {
	got := hex.EncodeToString(AuthzDigest([]byte("authorization-token-bytes")))
	const want = "d3d514caf1356899d1a45ce3dc4f812217bd7a0dfbae8ab164508bfb2d1a7b6f"
	if want != "GOLDEN" && got != want {
		t.Fatalf("authz-digest golden mismatch:\n got %s\nwant %s", got, want)
	}
	t.Logf("AUTHZ_DIGEST_GOLDEN=%s", got)
	if hex.EncodeToString(AuthzDigest(nil)) == got {
		t.Fatal("empty and non-empty authorization artifacts produced equal digests")
	}
}
