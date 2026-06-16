package awsiid

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// FuzzAWSIIDAttest hardens the AWS IMDSv2 instance-identity attester's untrusted
// entry point (Attest), which parses a caller-supplied CMS/PKCS#7 document BEFORE
// any trust is established (FUZZ-002). The payload flows attacker → safeParsePKCS7
// (the FUZZ-001 boundary) → JSON document decode → selector/claim extraction; no
// input — random bytes, the FUZZ-001 crasher 0x30 0x84, a validly-signed-but-
// untrusted doc, a CMS over malformed JSON — may panic. Attest must always return
// cleanly (an attestation or an error). Seeded with a valid IID-shaped CMS so the
// corpus exercises the happy path too, not only garbage.
func FuzzAWSIIDAttest(f *testing.F) {
	doc := []byte(`{"instanceId":"i-0abc123","accountId":"111122223333","region":"us-east-1","instanceType":"m5.large","imageId":"ami-1"}`)
	validP7, root, err := crypto.SignCMS(doc)
	if err != nil {
		f.Fatal(err)
	}
	// A CMS over a non-JSON body (signature is valid, payload is not a document).
	badBodyP7, _, err := crypto.SignCMS([]byte("not-json"))
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte(nil))
	f.Add([]byte{0x30, 0x84})                   // the FUZZ-001 crasher
	f.Add([]byte{0x30, 0x84, 0x00, 0x00, 0x00}) // long-form length, truncated body
	f.Add([]byte("not der at all"))
	f.Add(validP7)
	f.Add(badBodyP7)

	a := &Attestor{Roots: [][]byte{root}}
	f.Fuzz(func(t *testing.T, payload []byte) {
		// Only the absence of a panic is asserted; a verified-but-untrusted or
		// malformed document legitimately returns an error.
		_, _ = a.Attest(context.Background(), payload)
	})
}
