// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"testing"
	"time"
)

func TestHierarchyCARequiresVisibleCommonName(t *testing.T) {
	key, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	if _, err := SelfSignedHierarchyCA(key, HierarchyCAProfile{CommonName: "  ", TTL: 24 * time.Hour}); err == nil {
		t.Fatal("blank CA common name was accepted")
	}
}
