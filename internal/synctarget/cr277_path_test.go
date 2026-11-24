// SPDX-License-Identifier: BUSL-1.1

package synctarget

import "testing"

func TestCR277PathTargetsRejectDotSegments(t *testing.T) {
	for _, typ := range []string{"rundeck", "ovh-secret-manager"} {
		target, ok := Lookup(typ)
		if !ok {
			t.Fatalf("missing %s target", typ)
		}
		for _, key := range []string{".", "..", "project/../other", "./other", "project/./key"} {
			if err := target.ValidKey(key); err == nil {
				t.Errorf("%s accepted unsafe key %q", typ, key)
			}
		}
		if err := target.ValidKey("project/v1..2/key"); err != nil {
			t.Errorf("%s rejected ordinary dotted key: %v", typ, err)
		}
	}
	for _, folder := range []string{"folder keys/..", "folder keys/project/../other", "folder keys/./other"} {
		if _, err := ParseBinding("rundeck", folder); err == nil {
			t.Errorf("Rundeck accepted unsafe folder %q", folder)
		}
	}
}
