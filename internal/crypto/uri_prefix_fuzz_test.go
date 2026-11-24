// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"strings"
	"testing"
)

func FuzzCR803URIPrefix(f *testing.F) {
	f.Fuzz(func(t *testing.T, prefix, requested string) {
		_ = URIPrefixPermitted(requested, []string{prefix})
		if err := ValidateURIPrefix(prefix); err == nil &&
			!URIPrefixPermitted(strings.TrimSpace(prefix), []string{prefix}) {
			t.Fatalf("accepted URI prefix %q does not admit itself", prefix)
		}
	})
}
