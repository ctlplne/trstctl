// SPDX-License-Identifier: BUSL-1.1

package bcfks

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"
)

// x2l2Store is a BCFKS store made by keytool with the Bouncy Castle provider
// (OpenJDK 21.0.13 and libbcprov-java 1.77 on Ubuntu 24.04,
// drafts/x2l2/make.sh), store password changeit: key entries web (RSA-2048)
// and api-ec (EC P-256), secret keys db-master (AES-256) and hmac
// (HmacSHA256), and a trusted certificate partner-root. The provider wrote it
// with PBKDF2-HMAC-SHA512 (51,200 iterations), AES-256-CCM and an
// HMAC-SHA512 integrity check.
const x2l2Store = "testdata/x2l2-keytool.bcfks"

func fixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(x2l2Store)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func describe(entries []Entry) string {
	var out []string
	for _, e := range entries {
		kind := "trusted"
		switch {
		case e.SecretKey:
			kind = "secret"
		case e.KeyEntry:
			kind = "key"
		}
		var names []string
		for _, der := range e.ChainDER {
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				names = append(names, "unparsable")
				continue
			}
			names = append(names, cert.Subject.CommonName)
		}
		out = append(out, e.Alias+"="+kind+"["+strings.Join(names, ",")+"]")
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

// X2-L2: a BCFKS store opens with its password — its MAC checked, its store
// decrypted — and lists its key entries with their chains, its secret keys
// and its trusted certificate; a wrong password or a changed byte is refused.
func TestEntriesReadsAKeytoolBCFKSStoreX2L2(t *testing.T) {
	data := fixture(t)
	if !IsBCFKS(data) {
		t.Fatal("the fixture is not recognized as BCFKS")
	}
	if p12, err := os.ReadFile("../pfx/testdata/x2l1-java-multi-key.p12"); err != nil || IsBCFKS(p12) {
		t.Fatalf("a PKCS#12 file reads as BCFKS (%v)", err)
	}
	entries, err := Entries(data, []byte("changeit"))
	if err != nil {
		t.Fatal(err)
	}
	const want = "api-ec=key[api.x2l2.test] db-master=secret[] hmac=secret[] partner-root=trusted[X2-L2 Partner Root] web=key[web.x2l2.test]"
	if got := describe(entries); got != want {
		t.Fatalf("entries = %s\nwant %s", got, want)
	}
	if _, err := Entries(data, []byte("not-the-store-password")); !errors.Is(err, ErrIncorrectPassword) {
		t.Fatalf("a wrong password: %v", err)
	}
	tampered := bytes.Clone(data)
	tampered[len(tampered)/2] ^= 0x01 // inside the encrypted store
	if _, err := Entries(tampered, []byte("changeit")); !errors.Is(err, ErrIncorrectPassword) {
		t.Fatalf("a changed store byte: %v", err)
	}
}

// CCM authenticates the store on its own: with the integrity MAC bypassed, a
// changed ciphertext byte still fails to open.
func TestStoreDecryptionAuthenticatesX2L2(t *testing.T) {
	var store objectStore
	if _, err := asn1.Unmarshal(fixture(t), &store); err != nil {
		t.Fatal(err)
	}
	if _, err := openStore(store.StoreData.FullBytes, []byte("changeit")); err != nil {
		t.Fatalf("the store does not open: %v", err)
	}
	changed := bytes.Clone(store.StoreData.FullBytes)
	changed[len(changed)-3] ^= 0x80
	if _, err := openStore(changed, []byte("changeit")); !errors.Is(err, ErrIncorrectPassword) {
		t.Fatalf("a changed ciphertext opened: %v", err)
	}
}

// A store asking for more PBKDF2 work than the bound, or an unusable salt or
// key size, is refused before any hashing.
func TestKeyDerivationIsBoundedX2L2(t *testing.T) {
	prf := algorithmIdentifier{Algorithm: oidHMACSHA512, Parameters: asn1.NullRawValue}
	for name, params := range map[string]pbkdf2Params{
		"too many iterations": {Salt: make([]byte, 16), Iterations: maxIterations + 1, KeyLength: 32, PRF: prf},
		"no salt":             {Salt: nil, Iterations: 1000, KeyLength: 32, PRF: prf},
		"an oversized key":    {Salt: make([]byte, 16), Iterations: 1000, KeyLength: 1 << 20, PRF: prf},
	} {
		raw, err := asn1.Marshal(params)
		if err != nil {
			t.Fatal(err)
		}
		kdf := algorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: raw}}
		if _, err := deriveKey(kdf, []byte("changeit"), purposeStore, 32); !errors.Is(err, errUnsupported) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
