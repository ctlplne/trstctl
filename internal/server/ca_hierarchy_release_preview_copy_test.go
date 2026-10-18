// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"strings"
	"testing"
)

func TestManagedLeafReleasePreviewDescribesExactDispositionProof(t *testing.T) {
	steps := strings.Join(ceremonyPreviewVerification("release_managed_ca_leaf"), " ")
	for _, fact := range []string{"certificate", "release", "retirement checklist", "audit"} {
		if !strings.Contains(strings.ToLower(steps), fact) {
			t.Fatalf("release proof omits %q: %s", fact, steps)
		}
	}
	for _, unrelated := range []string{"authority status", "signer custody"} {
		if strings.Contains(strings.ToLower(steps), unrelated) {
			t.Fatalf("release proof contains unrelated CA mint check %q: %s", unrelated, steps)
		}
	}
}
