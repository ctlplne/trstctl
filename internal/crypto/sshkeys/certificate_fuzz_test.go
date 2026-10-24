// SPDX-License-Identifier: BUSL-1.1

package sshkeys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzParseCertificate(f *testing.F) {
	for _, name := range []string{"host-cert.pub", "forever-cert.pub", "user-cert.pub", "tampered-cert.pub", "host.pub"} {
		data, err := os.ReadFile(filepath.Join("testdata", name)) // #nosec G304 -- committed test fixture
		if err != nil {
			f.Fatal(err)
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
