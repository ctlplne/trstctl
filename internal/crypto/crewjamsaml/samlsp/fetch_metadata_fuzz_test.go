// SPDX-License-Identifier: BUSL-1.1

package samlsp

import "testing"

// FuzzParseMetadata exercises both the direct EntityDescriptor and wrapped
// EntitiesDescriptor XML paths with bytes supplied by an untrusted IdP.
func FuzzParseMetadata(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte("<EntityDescriptor/>"))
	f.Add([]byte("<EntitiesDescriptor><EntityDescriptor/></EntitiesDescriptor>"))
	f.Add([]byte("<EntitiesDescriptor><EntityDescriptor><IDPSSODescriptor/></EntityDescriptor></EntitiesDescriptor>"))
	f.Add([]byte("<EntityDescriptor><broken>"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		_, _ = ParseMetadata(data)
	})
}
