// SPDX-License-Identifier: BUSL-1.1

package rpverify_test

import (
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/translog"
)

// realProofFor appends leaf to a real signed transparency log (padded with other
// entries so the tree is non-trivial) and returns the encoded, self-contained
// inclusion proof plus the log's public key. Tests use it instead of a mock closure
// so the relying-party inclusion check exercises the REAL RFC-6962 verifier (INT-18).
func realProofFor(t *testing.T, leaf []byte) (proofBytes, logPubDER []byte) {
	t.Helper()
	logKey, err := crypto.NewSoftwareBackend().GenerateKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	l := translog.New(logKey)
	if _, _, err := l.Append([]byte("other-leaf-a")); err != nil {
		t.Fatal(err)
	}
	idx, _, err := l.Append(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.Append([]byte("other-leaf-b")); err != nil {
		t.Fatal(err)
	}
	p, err := l.Prove(idx)
	if err != nil {
		t.Fatal(err)
	}
	return translog.EncodeProof(p), logKey.Public().DER
}
