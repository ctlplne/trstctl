// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePolicy lays out a crypto-policies root: config, and when groups is
// not empty the OpenSSL back-end with that Groups line.
func writePolicy(t *testing.T, name, groups string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "config"), []byte("# set by update-crypto-policies\n"+name+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if groups != "" {
		if err := os.MkdirAll(filepath.Join(root, "back-ends"), 0o750); err != nil {
			t.Fatal(err)
		}
		cnf := "CipherString = @SECLEVEL=2:kEECDH:kRSA\nCiphersuites = TLS_AES_256_GCM_SHA384\n[ssl_default]\nGroups = " + groups + "\n"
		if err := os.WriteFile(filepath.Join(root, "back-ends", "opensslcnf.config"), []byte(cnf), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// X2-L6: the system crypto policy is read from /etc/crypto-policies: its
// name, and whether its OpenSSL back-end keeps the ML-KEM hybrid groups in
// the TLS defaults. LEGACY says what it weakens; a policy file that is not a
// policy name, or a host with none, reports nothing.
func TestCryptoPolicyIsReadWithItsMLKEMAnswerX2L6(t *testing.T) {
	for _, tc := range []struct {
		name, groups, want string
		legacy             bool
	}{
		{"DEFAULT", "*X25519MLKEM768:*x25519:secp256r1:x448", PQHybridYes, false},
		{"DEFAULT:PQ", "?SecP256r1MLKEM768:X25519:secp256r1", PQHybridYes, false},
		{"FUTURE", "X25519:secp384r1:x448", PQHybridNo, false},
		{"LEGACY:AD-SUPPORT", "X25519:secp256r1:ffdhe2048", PQHybridNo, true},
		{"FIPS", "", PQHybridUnknown, false},
	} {
		found, ok := ReadCryptoPolicy(writePolicy(t, tc.name, tc.groups))
		if !ok || found.Library != CryptoPolicyLibrary || found.Version != tc.name || found.PQHybrid != tc.want {
			t.Fatalf("%s: %+v %v, want answer %s", tc.name, found, ok, tc.want)
		}
		if CryptoPolicyIsLegacy(found.Version) != tc.legacy || strings.Contains(found.Basis, "SHA-1") != tc.legacy {
			t.Fatalf("%s: legacy %v, basis %q", tc.name, tc.legacy, found.Basis)
		}
	}
	if _, ok := ReadCryptoPolicy(t.TempDir()); ok {
		t.Fatal("a host with no policy reported one")
	}
	if _, ok := ReadCryptoPolicy(writePolicy(t, "default; rm -rf /", "")); ok {
		t.Fatal("a policy file that is not a policy name was reported")
	}

	// The library source reports the policy beside the libraries it reads.
	root := writePolicy(t, "DEFAULT", "X25519:secp256r1")
	found, err := NewCryptoLibrarySource(nil, nil).WithCryptoPolicy(root).Discover(context.Background())
	if err != nil || len(found) != 1 || found[0].Library != CryptoPolicyLibrary || found[0].PQHybrid != PQHybridNo ||
		!strings.Contains(found[0].Basis, "leaves the ML-KEM hybrid groups out") {
		t.Fatalf("source: %+v %v", found, err)
	}
	if found, err := NewCryptoLibrarySource(nil, nil).Discover(context.Background()); err != nil || len(found) != 0 {
		t.Fatalf("a source with no policy root read one: %+v %v", found, err)
	}
}
