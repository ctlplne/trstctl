// SPDX-License-Identifier: BUSL-1.1

package secretscan

import "testing"

// The scanner-report parsers ingest untrusted JSON from external tools, so they
// are fuzzed for the "never panics" property (TEST-FUZZASSERT-001). A malformed report must
// fail closed, never crash the ingest path — and never surface a secret value
// (the Finding type structurally cannot carry one).

func FuzzParseGitleaks(f *testing.F) {
	f.Add([]byte(`[{"RuleID":"x","File":"f","StartLine":1}]`))
	f.Add([]byte(`[`))
	f.Add([]byte(``))
	f.Add([]byte(`[{}]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseGitleaks(b)
	})
}

func FuzzParseTrufflehog(f *testing.F) {
	f.Add([]byte(`{"DetectorName":"AWS","SourceMetadata":{"Data":{"Filesystem":{"file":"f","line":1}}}}`))
	f.Add([]byte("\n\n"))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseTrufflehog(b)
	})
}
