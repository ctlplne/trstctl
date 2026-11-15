// SPDX-License-Identifier: BUSL-1.1

package cbom

import (
	"strings"
	"testing"
)

// X2-L5R: a host agent's libraries and keystore keys are classified as CBOM
// assets. A library is rated by whether it can negotiate X25519MLKEM768
// (strong; quantum-vulnerable; unknown claims nothing), whatever else the
// finding carries; a keystore key by its type and size, as a certificate key
// is. A library's migration is its key establishment. The CycloneDX export
// writes neither from the inventory: it carries both once, from the agents'
// findings.
func TestHostAgentLibrariesAndKeystoreKeysAreClassifiedX2L5R(t *testing.T) {
	p := DefaultPolicy()
	for _, tc := range []struct {
		pq       string
		strength Strength
		qv       bool
		reason   string
	}{
		{PQHybridYes, StrengthStrong, false, "openssl 3.5.9 can negotiate the X25519MLKEM768 post-quantum hybrid: OpenSSL 3.5 and later"},
		{PQHybridNo, StrengthAcceptable, true, "openssl 3.5.9 cannot negotiate X25519MLKEM768, so its TLS key exchanges are breakable"},
		{PQHybridUnknown, StrengthAcceptable, false, "whether openssl 3.5.9 can negotiate X25519MLKEM768 is not known"},
	} {
		f := Finding{Kind: AssetCryptoLibrary, Location: "web-01:/usr/lib/libcrypto.so.3", Library: "openssl", ProductVersion: "openssl 3.5.9",
			Algorithm: "RSA", KeyBits: 1024, PQHybrid: tc.pq, PQBasis: "OpenSSL 3.5 and later"}.Classified(p)
		if f.Class.Strength != tc.strength || f.Class.QuantumVulnerable != tc.qv || f.Class.OutOfPolicy || len(f.Class.Reasons) != 1 ||
			!strings.HasPrefix(f.Class.Reasons[0], tc.reason) {
			t.Errorf("library %s = %+v", tc.pq, f.Class)
		}
		if target := MigrationTargetFor(f); target.Algorithm != "licensed-key-establishment-transition" || target.Generation != GenerationMigrationRequired {
			t.Errorf("library %s target = %+v", tc.pq, target)
		}
	}
	for _, tc := range []struct {
		algorithm string
		bits      int
		strength  Strength
		qv, oop   bool
	}{
		{"RSA", 2048, StrengthAcceptable, true, false},
		{"RSA", 1024, StrengthWeak, true, true},
		{"EC", 256, StrengthAcceptable, true, false},
	} {
		f := Finding{Kind: AssetKeystoreKey, Location: "web-01:/opt/app/keystore.p12#tomcat", Algorithm: tc.algorithm, KeyBits: tc.bits}.Classified(p)
		if f.Class.Strength != tc.strength || f.Class.QuantumVulnerable != tc.qv || f.Class.OutOfPolicy != tc.oop {
			t.Errorf("keystore key %s-%d = %+v", tc.algorithm, tc.bits, f.Class)
		}
	}
	bom := CycloneDXWith([]CycloneDXAsset{
		{ID: "a1", Kind: string(AssetCryptoLibrary), Location: "web-01:/usr/lib/libcrypto.so.3", Library: "openssl", Strength: "strong"},
		{ID: "a2", Kind: string(AssetKeystoreKey), Location: "web-01:/opt/app/keystore.p12#tomcat", Algorithm: "RSA", KeyBits: 2048, Strength: "acceptable"},
		{ID: "a4", Kind: string(AssetKeyFile), Location: "web-01:/etc/ssl/private/web.key", Algorithm: "ECDSA", KeyBits: 256, Strength: "acceptable"},
		{ID: "a3", Kind: string(AssetTLSEndpoint), Location: "web-01:443", Protocol: "TLSv1.3", Strength: "strong"},
	}, CycloneDXSupplement{Libraries: []CycloneDXLibrary{{ID: "f1", Name: "openssl", Version: "3.5.9", Location: "/usr/lib/libcrypto.so.3", PQHybrid: "yes"}}},
		CycloneDXMeta{})
	assets, libraries := 0, 0
	for _, c := range bom.Components {
		switch c.Type {
		case "cryptographic-asset":
			assets++
		case "library":
			libraries++
		}
	}
	if assets != 1 || libraries != 1 {
		t.Fatalf("export has %d inventory components and %d libraries; want the TLS endpoint alone and the library once", assets, libraries)
	}
}
