// SPDX-License-Identifier: BUSL-1.1

package sshkeys

import (
	"embed"
	"strings"
	"testing"
)

// certificateSeeds are the fuzz seeds, compiled in: the ClusterFuzzLite runner
// has no source tree to read them from.
//
//go:embed testdata/host-cert.pub testdata/forever-cert.pub testdata/user-cert.pub testdata/tampered-cert.pub testdata/host.pub
var certificateSeeds embed.FS

func FuzzParseCertificate(f *testing.F) {
	for _, name := range []string{"host-cert.pub", "forever-cert.pub", "user-cert.pub", "tampered-cert.pub", "host.pub"} {
		data, err := certificateSeeds.ReadFile("testdata/" + name)
		if err != nil {
			f.Fatal(err)
			return // the ClusterFuzzLite shim's Fatal returns
		}
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		info, err := ParseCertificate(data)
		if err != nil {
			return
		}
		if (info.Kind != "host" && info.Kind != "user") || !strings.HasPrefix(info.CAFingerprintSHA256, "SHA256:") ||
			!strings.HasPrefix(info.KeyFingerprintSHA256, "SHA256:") || (info.Forever && !info.ValidBefore.IsZero()) {
			t.Fatalf("parsed certificate without kind, fingerprints or a consistent window: %+v", info)
		}
	})
}
