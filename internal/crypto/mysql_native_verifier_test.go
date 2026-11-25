// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"testing"

	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestMySQLNativePasswordVerifierMariaDBReferenceVectorCR596(t *testing.T) {
	verifier, err := MySQLNativePasswordVerifier([]byte("mariadb"))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(verifier)
	if !bytes.Equal(verifier, []byte("*54958E764CE10E50764C2EECBB71D01F08549980")) {
		t.Fatal("MariaDB verifier differs from its published PASSWORD('mariadb') vector")
	}
}
