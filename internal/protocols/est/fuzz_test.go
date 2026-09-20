// SPDX-License-Identifier: BUSL-1.1

package est

import (
	"strings"
	"testing"
)

// FuzzParseEnrollBody hardens the EST wire parser: no input — random bytes, near-
// base64, base64 of garbage — may crash it; it must always return cleanly (a CSR
// or an error), never panic. It runs in the CI fuzz-smoke job and the
// ClusterFuzzLite continuous-fuzzing config (.clusterfuzzlite/) alongside the
// other parsers, with a committed seed corpus under testdata/fuzz (FUZZ-003).
func FuzzParseEnrollBody(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("MIIB"))             // truncated base64
	f.Add([]byte("not base64 !!!"))   // invalid base64
	f.Add([]byte("aGVsbG8gd29ybGQ=")) // base64 of "hello world" (not a CSR)
	f.Add([]byte(strings.Repeat("A", 1000)))

	f.Fuzz(func(t *testing.T, body []byte) {
		der, err := parseEnrollBody(strings.NewReader(string(body)))
		if err != nil && der != nil {
			t.Fatalf("parseEnrollBody returned both a CSR and an error")
		}
	})
}
