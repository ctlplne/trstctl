// SPDX-License-Identifier: BUSL-1.1
package store

import (
	"testing"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Native internal target, auto-discovered by the existing fuzz build. Input
// example size bounds the fuzz campaign, not the supported snapshot size.
func FuzzProtectedSnapshotPayload(f *testing.F) {
	metadata, raw, provider := newSnapshotProtectionFixture(f, "snapshot fuzz fixture")
	defer secret.Wipe(raw)
	encoded, err := protectSnapshotPayload(f.Context(), snapshotProtectionFixtureTenant, metadata, raw, provider)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Add([]byte(`{"_trstctl_snapshot_protection":null}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		opened, _ := openSnapshotPayload(t.Context(), snapshotProtectionFixtureTenant, metadata, data, provider)
		secret.Wipe(opened)
	})
}
