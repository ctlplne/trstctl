// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"context"
	"path/filepath"
	"testing"
)

// X2-L4R: BoringSSL, AWS-LC and wolfSSL are rated by what each build names.
// The strings are those of stock builds read in the lab: Alpine's wolfssl
// 5.9.4-r0 ("wolfSSL 5.9.4", its wolfSSL_lib_version API and the
// X25519MLKEM768, SecP256r1MLKEM768 and SecP384r1MLKEM1024 groups) and
// wolfssl-fast 5.9.4-r0 (its version alone); Alpine's aws-lc 5.0.0-r3
// (libcrypto naming "AWS-LC 5.0.0" and the hybrids, libssl beside it naming
// them too); and the android-libboringssl packages of Ubuntu 24.04
// (14.0.0+r11: "BoringSSL", X25519 and the pre-standard X25519Kyber768 and
// P256Kyber768) and Debian 12 (13.0.0+r24: "BoringSSL" and X25519 alone). A
// wolfSSL built without ML-KEM and a BoringSSL whose libssl alone names
// X25519MLKEM768 stand for the builds the lab had no package of.
func TestBoringSSLAWSLCAndWolfSSLAreRatedX2L4R(t *testing.T) {
	root := t.TempDir()
	at := func(parts ...string) string { return filepath.Join(append([]string{root}, parts...)...) }
	writeLib(t, at("alpine", "usr", "lib", "libwolfssl.so.46.0.0"), "wolfSSL 5.9.4", "5.9.4", "wolfSSL_lib_version", "wolfSSL_lib_version_hex",
		"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024")
	writeLib(t, at("alpine-fast", "usr", "lib", "libwolfssl.so.46.0.0"), "5.9.4", "wolfSSL_lib_version", "X25519MLKEM768")
	writeLib(t, at("classic", "lib", "libwolfssl.so.42"), "wolfSSL 5.6.6", "wolfSSL_lib_version", "x25519")
	writeLib(t, at("awslc", "usr", "lib", "libcrypto.so"), "AWS-LC 5.0.0", "AWS-LC KEM method", "SecP256r1MLKEM768", "X25519MLKEM768")
	writeLib(t, at("awslc", "usr", "lib", "libssl.so"), "SecP256r1MLKEM768", "X25519MLKEM768")
	writeLib(t, at("noble", "usr", "lib", "android", "libcrypto.so.0"), "BoringSSL", "P-256", "P-384", "X25519", "P256Kyber768", "P384Kyber768", "X25519Kyber768")
	writeLib(t, at("noble", "usr", "lib", "android", "libssl.so.0"), "P-256", "P-384", "X25519", "x25519", "N4bssl12_GLOBAL__N_122X25519Kyber768KeyShareE")
	writeLib(t, at("bookworm", "usr", "lib", "android", "libcrypto.so.0"), "BoringSSL", "P-256", "P-384", "X25519")
	writeLib(t, at("bookworm", "usr", "lib", "android", "libssl.so.0"), "P-256", "P-384", "X25519", "x25519")
	writeLib(t, at("current", "lib", "libcrypto.so"), "OpenSSL 1.1.1 (compatible; BoringSSL)")
	writeLib(t, at("current", "lib", "libssl.so"), "X25519", "x25519", "X25519MLKEM768")

	found, err := NewCryptoLibrarySource([]string{root}, nil).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]LibraryFound{}
	for _, f := range found {
		rel, _ := filepath.Rel(root, f.Location)
		got[filepath.ToSlash(rel)] = f
	}
	for rel, want := range map[string]struct{ library, version, pq string }{
		"alpine/usr/lib/libwolfssl.so.46.0.0":      {"wolfssl", "5.9.4", PQHybridYes},
		"alpine-fast/usr/lib/libwolfssl.so.46.0.0": {"wolfssl", "5.9.4", PQHybridYes},
		"classic/lib/libwolfssl.so.42":             {"wolfssl", "5.6.6", PQHybridNo},
		"awslc/usr/lib/libcrypto.so":               {"aws-lc", "5.0.0", PQHybridYes},
		"noble/usr/lib/android/libcrypto.so.0":     {"boringssl", "unversioned", PQHybridNo},
		"bookworm/usr/lib/android/libcrypto.so.0":  {"boringssl", "unversioned", PQHybridNo},
		"current/lib/libcrypto.so":                 {"boringssl", "unversioned", PQHybridYes},
	} {
		f, ok := got[rel]
		if !ok || f.Library != want.library || f.Version != want.version || f.PQHybrid != want.pq || f.Basis == "" {
			t.Errorf("%s = %+v; want %s %s, pq %s", rel, f, want.library, want.version, want.pq)
		}
	}
	if f := got["noble/usr/lib/android/libcrypto.so.0"]; f.Basis != "this BoringSSL build names only the pre-standard Kyber768 hybrids (X25519Kyber768Draft00), not X25519MLKEM768 (BoringSSL has no release versions)" {
		t.Errorf("the Kyber768 BoringSSL's basis: %q", f.Basis)
	}
	if len(got) != 7 {
		t.Errorf("found %d libraries, want 7 (a libssl beside its libcrypto is not reported twice): %v", len(got), got)
	}
}

// FuzzIdentifyLibraryX2L4R drives hostile bytes through library
// identification, a jar manifest's parser and java.security's provider list
// (X2-L4R): nothing panics, and a library found has a version, an answer and
// its reason.
func FuzzIdentifyLibraryX2L4R(f *testing.F) {
	for _, seed := range []string{
		"\x00wolfSSL 5.9.4\x005.9.4\x00wolfSSL_lib_version\x00X25519MLKEM768\x00SecP256r1MLKEM768\x00",
		"\x005.9.4\x00wolfSSL_lib_version\x00",
		"\x00AWS-LC 5.0.0\x00AWS-LC KEM method\x00X25519MLKEM768\x00",
		"\x00BoringSSL\x00P-256\x00X25519\x00X25519Kyber768\x00",
		"OpenSSL 1.1.1 (compatible; BoringSSL)",
		"Manifest-Version: 1.0\r\nAutomatic-Module-Name: org.bouncycastle.tls\r\nImplementation-Version: 1.77.00.0\r\n continued\r\n\r\nName: x\r\n",
		"security.provider.2=SunRsaSign\nsecurity.provider.1=SUN\n#security.provider.3=Off\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, name := range []string{"libwolfssl.so.46", "libcrypto.so.0", "libcrypto.so"} {
			found, ok := identifyLibrary(filepath.Join("/nonexistent-x2l4r", name), data)
			if ok && (found.Library == "" || found.Version == "" || found.PQHybrid == "" || found.Basis == "") {
				t.Fatalf("%s: %+v", name, found)
			}
		}
		_ = trimZeroComponents(manifestAttributes(data)["Implementation-Version"])
		if providers := javaProviders(data); len(providers) > maxJavaProviders {
			t.Fatalf("%d providers listed", len(providers))
		}
	})
}
