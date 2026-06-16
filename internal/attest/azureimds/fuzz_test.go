package azureimds

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// FuzzAzureIMDSAttest hardens the Azure IMDS attested-data attester's untrusted
// entry point (Attest), which parses a caller-supplied CMS/PKCS#7 document BEFORE
// any trust is established (FUZZ-002). The payload flows attacker → safeParsePKCS7
// (the FUZZ-001 boundary) → JSON document decode → selector/claim extraction; no
// input — random bytes, the FUZZ-001 crasher 0x30 0x84, a validly-signed-but-
// untrusted doc, a CMS over malformed JSON — may panic. Attest must always return
// cleanly. Seeded with a valid attested-document CMS so the corpus exercises the
// happy path too.
func FuzzAzureIMDSAttest(f *testing.F) {
	doc := []byte(`{"vmId":"vm-1","subscriptionId":"sub-1","resourceGroupName":"rg","location":"westus","name":"node-1"}`)
	validP7, root, err := crypto.SignCMS(doc)
	if err != nil {
		f.Fatal(err)
	}
	badBodyP7, _, err := crypto.SignCMS([]byte("not-json"))
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte(nil))
	f.Add([]byte{0x30, 0x84})                   // the FUZZ-001 crasher
	f.Add([]byte{0x30, 0x84, 0x00, 0x00, 0x00}) // long-form length, truncated body
	f.Add([]byte("garbage"))
	f.Add(validP7)
	f.Add(badBodyP7)

	a := &Attestor{Roots: [][]byte{root}}
	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = a.Attest(context.Background(), payload)
	})
}
