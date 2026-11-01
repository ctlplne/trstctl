// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	cryptoboundary "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jks"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/pfx"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// X2: keystores on a host appear as key entries with key type and size, a JKS
// without its password is listed unverified, a locked PKCS#12 file is reported
// locked, and no finding carries key material.
func TestKeystoreSourceReportsKeyEntriesWithoutKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	ca, err := mtls.NewCA("x2-keystore-ca")
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := cryptoboundary.GenerateHostSubjectKey("app.example.test", []string{"app.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer hostKey.Destroy()
	keyPEM, err := hostKey.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(keyPEM)
	// The test CA returns the leaf and its CA as PEM: a two-certificate chain.
	certPEM, err := ca.SignClientCSR(hostKey.CSRDER, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	jksData, err := jks.EncodeDeterministic(keyPEM, certPEM, "storepass", "tomcat")
	if err != nil {
		t.Fatal(err)
	}
	p12Data, err := pfx.EncodeDeterministic(keyPEM, certPEM, "p12pass")
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"conf/server.jks": jksData, "conf/client.p12": p12Data, "locked/other.pfx": p12Data, "conf/readme.txt": []byte("not a keystore"),
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	found, err := NewKeystoreSource([][]byte{[]byte("p12pass")}, filepath.Join(dir, "conf")).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byFormat := map[string]PrivateKeyFound{}
	for _, f := range found {
		byFormat[f.Format] = f
		if f.Source != SourceKeystore || f.Algorithm == "" || f.Fingerprint == "" || f.FingerprintBasis != "public-spki-sha256" {
			t.Fatalf("keystore finding = %+v", f)
		}
		for k, v := range f.Metadata {
			if strings.Contains(v, "PRIVATE KEY") || strings.Contains(v, string(keyPEM[40:80])) {
				t.Fatalf("finding metadata %s carries key material", k)
			}
		}
	}
	jksFound, p12Found := byFormat["JKS"], byFormat["PKCS12"]
	if len(found) != 2 || jksFound.Location != filepath.Join(dir, "conf/server.jks")+"#tomcat" || jksFound.Metadata["keystore_alias"] != "tomcat" ||
		jksFound.Metadata["integrity_verified"] != "false" || p12Found.Metadata["integrity_verified"] != "true" ||
		jksFound.Fingerprint != p12Found.Fingerprint || jksFound.Algorithm != p12Found.Algorithm ||
		jksFound.Metadata["key_type"] != "ECDSA" || jksFound.Metadata["key_size_bits"] != "256" || jksFound.Metadata["chain_length"] != "2" {
		t.Fatalf("keystores = %+v", found)
	}

	locked, err := NewKeystoreSource(nil, filepath.Join(dir, "locked", "*.pfx")).Discover(context.Background())
	if err != nil || len(locked) != 1 || locked[0].Metadata["keystore_state"] != "locked" || locked[0].Fingerprint != "" {
		t.Fatalf("locked PKCS#12 = %+v, %v", locked, err)
	}
}

// X2: a host's OpenSSL version says whether it can negotiate X25519MLKEM768,
// a Go program's build information says the same, and unidentified files are
// never reported.
func TestCryptoLibrarySourceRatesX25519MLKEM768(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("\x7fELF\x00padding\x00"+body+"\x00tail"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	newSSL := write("libcrypto.so.3", "OpenSSL 3.5.1 1 Jul 2025")
	oldSSL := write("libssl.so.3.0", "OpenSSL 3.0.13 30 Jan 2024")
	write("libcrypto.so.1.1", "OpenSSL 1.1.1w  11 Sep 2023")
	write("libcrypto-boring.so", "OpenSSL 1.1.1 (compatible; BoringSSL)")
	write("libunrelated.so", "OpenSSL 3.5.1 1 Jul 2025")
	write("libcrypto.so.99", "no version string here")

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	found, err := NewCryptoLibrarySource([]string{dir}, []string{self}).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]LibraryFound{}
	for _, f := range found {
		got[filepath.Base(f.Location)] = f
	}
	if f := got["libcrypto.so.3"]; f.Location != newSSL || f.Library != "openssl" || f.Version != "3.5.1" || f.PQHybrid != PQHybridYes {
		t.Fatalf("OpenSSL 3.5.1 = %+v", f)
	}
	if f := got["libssl.so.3.0"]; f.Location != oldSSL || f.Version != "3.0.13" || f.PQHybrid != PQHybridNo || f.Basis == "" {
		t.Fatalf("OpenSSL 3.0.13 = %+v", f)
	}
	if f := got["libcrypto.so.1.1"]; f.Version != "1.1.1w" || f.PQHybrid != PQHybridNo {
		t.Fatalf("OpenSSL 1.1.1w = %+v", f)
	}
	if f := got["libcrypto-boring.so"]; f.Library != "boringssl" || f.PQHybrid != PQHybridUnknown {
		t.Fatalf("BoringSSL = %+v", f)
	}
	if _, ok := got["libunrelated.so"]; ok {
		t.Fatal("a directory walk read a file that is not named like a TLS library")
	}
	if _, ok := got["libcrypto.so.99"]; ok {
		t.Fatal("a library without a version string was reported")
	}
	program := got[filepath.Base(self)]
	if program.Library != "go" || !strings.HasPrefix(runtime.Version(), "go"+program.Version) || program.PQHybrid != PQHybridYes {
		t.Fatalf("this Go %s test binary = %+v", runtime.Version(), program)
	}
}
