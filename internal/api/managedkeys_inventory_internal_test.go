// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/store"
)

func TestManagedKeyResponsesDoNotClaimLegacyCloudDeletionIsComplete(t *testing.T) {
	legacy := store.ManagedKey{Provider: "aws-kms", KeyID: "opaque-kms-key", State: "zeroized"}
	if got := toManagedKeyRecordResponse(legacy).State; got != "deletion_pending" {
		t.Fatalf("legacy cloud inventory state = %q, want deletion_pending", got)
	}
	if got := toManagedKeyResponse(ManagedKey{KeyID: legacy.KeyID, State: legacy.State}, legacy.Provider).State; got != "deletion_pending" {
		t.Fatalf("legacy cloud mutation response state = %q, want deletion_pending", got)
	}
	local := store.ManagedKey{Provider: "pkcs11", KeyID: "device-key", State: "zeroized"}
	if got := toManagedKeyRecordResponse(local).State; got != "zeroized" {
		t.Fatalf("confirmed device destruction state = %q, want zeroized", got)
	}
}

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
