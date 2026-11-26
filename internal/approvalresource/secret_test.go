// SPDX-License-Identifier: BUSL-1.1
package approvalresource_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/approvalresource"
)

func TestSecretApprovalIDPreservesExactNameC0086(t *testing.T) {
	for _, name := range []string{"db/password", "edge ", " edge", "edge\n", "secret-name-b64:ZWRnZSA"} {
		id := approvalresource.SecretID(name)
		decoded, ok := approvalresource.DecodeSecretID(id)
		if !ok || decoded != name {
			t.Fatalf("approval ID %q decoded as %q (%v), want %q", id, decoded, ok, name)
		}
		if strings.TrimSpace(name) != name && strings.TrimSpace(approvalresource.SecretDisplayName(name)) == name {
			t.Fatalf("edge whitespace is invisible in review name %q", name)
		}
	}
	for _, id := range []string{"secret:", "secret-name-b64:", "secret-name-b64:%%%", "secret:edge "} {
		if _, ok := approvalresource.DecodeSecretID(id); ok {
			t.Fatalf("ambiguous or malformed approval ID %q decoded", id)
		}
	}
}
