// SPDX-License-Identifier: BUSL-1.1

package mysqlsignin

import "testing"

func TestGatewayMySQLRejectsConnectionOptionsItCannotEnforce(t *testing.T) {
	for _, tc := range []struct{ name, query string }{
		{"file transfer", "allowAllFiles=true"},
		{"disabled TLS", "tls=false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, err := ParseDSN([]byte("review:plain@tcp(db.test:3306)/orders?" + tc.query))
			if target != nil {
				target.Wipe()
			}
			if err == nil {
				t.Fatal("the gateway accepted an option it cannot enforce")
			}
		})
	}
	if target, err := ParseDSN([]byte("review:plain@tcp(db.test:3306)/orders?tls=true")); err != nil {
		t.Fatalf("verified TLS option rejected: %v", err)
	} else {
		target.Wipe()
	}
}
