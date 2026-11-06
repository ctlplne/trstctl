// SPDX-License-Identifier: BUSL-1.1
package accessdesktop

import (
	"strings"
	"testing"
)

func TestBindingBounds(t *testing.T) {
	good := Binding{Address: "desktop.example:3389", CertificateSHA256: strings.Repeat("ab", 32), Width: 800, Height: 600}
	if good.Validate() != nil {
		t.Fatal("valid desktop refused")
	}
	for _, alter := range []func(*Binding){func(b *Binding) { b.Address = "desktop:0" }, func(b *Binding) { b.Address = "bad\thost:3389" }, func(b *Binding) { b.CertificateSHA256 = strings.Repeat("xy", 32) }, func(b *Binding) { b.Width = 1281 }, func(b *Binding) { b.Height = 199 }, func(b *Binding) { b.Domain = "domain\x00foreign" }} {
		bad := good
		alter(&bad)
		if bad.Validate() == nil {
			t.Fatal("invalid desktop accepted")
		}
	}
}
