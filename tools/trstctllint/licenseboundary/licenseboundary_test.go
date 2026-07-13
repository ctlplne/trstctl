// SPDX-License-Identifier: MPL-2.0

package licenseboundary

import "testing"

func TestPQCPlacementAllowsOnlyNonShippedEvidenceTooling(t *testing.T) {
	for _, path := range []string{
		"/workspace/trstctl/tools/dodcensus/runtime_runner.go",
		"/workspace/trstctl/tools/dodcensus/runtime_runner_test.go",
	} {
		if !isPQCAllowedCorePath(path) {
			t.Fatalf("DoD evidence tooling path %q was not allowed", path)
		}
	}
	for _, path := range []string{
		"/workspace/trstctl/internal/server/pqc_runtime.go",
		"/workspace/trstctl/internal/crypto/mldsa.go",
		"/workspace/trstctl/cmd/trstctl-agent/pqc.go",
	} {
		if isPQCAllowedCorePath(path) {
			t.Fatalf("shipped core product path %q bypassed PACKAGING-007", path)
		}
	}
}
