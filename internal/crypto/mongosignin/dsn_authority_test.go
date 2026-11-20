// SPDX-License-Identifier: BUSL-1.1

package mongosignin

import "testing"

func TestGatewayMongoRefusesFileOptionsInSessionCredential(t *testing.T) {
	for _, tc := range []struct{ name, option string }{
		{"root", "tlsCAFile=unused"},
		{"client certificate", "tlsCertificateKeyFile=unused"},
		{"key password", "tlsCertificateKeyFilePassword=plain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := ParseURI([]byte("mongodb://review:plain@db.test/orders?tls=true&" + tc.option))
			if parsed != nil {
				defer parsed.Wipe()
			}
			if err == nil {
				t.Fatal("the session credential supplied a file-backed trust option")
			}
		})
	}
}
