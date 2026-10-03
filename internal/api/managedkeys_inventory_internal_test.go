// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"strings"
	"testing"
)

func TestManagedKeyInventoryCursorBindsProviderAndKey(t *testing.T) {
	encoded := managedKeyCursor("aws-kms", "key-1")
	provider, keyID, err := parseManagedKeyCursor(encoded)
	if err != nil || provider != "aws-kms" || keyID != "key-1" {
		t.Fatalf("cursor round trip = %q %q %v", provider, keyID, err)
	}
	for _, invalid := range []string{"!", managedKeyCursor("", "key-1"), managedKeyCursor("aws-kms", ""), managedKeyCursor("aws-kms", "key\x00suffix"), strings.Repeat("a", 1025)} {
		if _, _, err := parseManagedKeyCursor(invalid); err == nil {
			t.Fatalf("accepted invalid inventory cursor %q", invalid)
		}
	}
}
