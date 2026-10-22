// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/seal"
)

// A77: the SP's assertion-encryption identity is generated once, sealed under
// the deployment KEK with its own purpose binding, and reloaded byte-for-byte
// by every later start; a protocol RA file is not accepted in its place.
func TestSAMLEncryptionIdentityIsSealedOnceAndReloaded(t *testing.T) {
	raw, err := seal.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	kek, err := seal.NewLocalKEK(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kek.Destroy)
	path := filepath.Join(t.TempDir(), "saml", "sp-encryption.sealed")
	certDER, keyPKCS8, err := SAMLEncryptionIdentity(path, kek)
	if err != nil || len(certDER) == 0 || len(keyPKCS8) == 0 {
		t.Fatalf("first identity = %d/%d bytes, %v", len(certDER), len(keyPKCS8), err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("sealed file = %v %v, want mode 0600", info, err)
	}
	again, againKey, err := SAMLEncryptionIdentity(path, kek)
	if err != nil || !bytes.Equal(again, certDER) || !bytes.Equal(againKey, keyPKCS8) {
		t.Fatalf("reloaded identity differs or failed: %v", err)
	}
	if _, _, err := loadProtocolTransportKey(path, kek); err == nil {
		t.Fatal("a SAML SP encryption file opened as a protocol RA identity")
	}
	if _, _, err := SAMLEncryptionIdentity(path, nil); err == nil || !strings.Contains(err.Error(), "KEK") {
		t.Fatalf("identity without a KEK = %v, want a refusal naming the KEK", err)
	}
	if _, _, err := SAMLEncryptionIdentity("", kek); err == nil {
		t.Fatal("identity without a path was accepted")
	}
}
