// SPDX-License-Identifier: BUSL-1.1

package jks

import (
	"bytes"
	"crypto/x509"
	"os"
	"sort"
	"strings"
	"testing"
)

// The fixtures are JCEKS keystores made by keytool (OpenJDK 21.0.13 on
// Ubuntu 24.04, drafts/x2l2/make.sh and make-secrets.sh) with Java's default
// store password: x2l2-keytool.jceks holds key entries web (RSA-2048) and
// api-ec (EC P-256), secret keys db-master (AES-256) and hmac (HmacSHA256),
// and a trusted certificate partner-root; x2l2-secrets-only.jceks holds two
// AES secret keys, the shape of a Hadoop credential store.
const (
	x2l2Keystore    = "testdata/x2l2-keytool.jceks"
	x2l2SecretsOnly = "testdata/x2l2-secrets-only.jceks" // #nosec G101 -- a fixture file path, not a credential (CWE-798)
)

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- the test reads its own fixture (CWE-22)
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

// X2-L2: a JCEKS keystore lists its key entries with their chains, its
// trusted certificate and its secret keys (stepped over, never unsealed),
// and checks the store password against its integrity digest.
func TestJCEKSEntriesReadsAKeytoolStoreX2L2(t *testing.T) {
	data := readFixture(t, x2l2Keystore)
	if !IsJCEKS(data) || IsJKS(data) {
		t.Fatal("the fixture is not recognized as JCEKS")
	}
	entries, verified, err := JCEKSEntries(data, [][]byte{[]byte("wrong"), []byte("changeit")})
	if err != nil {
		t.Fatal(err)
	}
	const want = "api-ec=key[api.x2l2.test] db-master=secret[] hmac=secret[] partner-root=trusted[X2-L2 Partner Root] web=key[web.x2l2.test]"
	if got := describe(entries); got != want || !verified {
		t.Fatalf("entries = %s (verified %v)\nwant %s (verified)", got, verified, want)
	}
	// Without the password the clear certificates are still listed, unverified.
	entries, verified, err = JCEKSEntries(data, nil)
	if err != nil || verified || describe(entries) != want {
		t.Fatalf("without its password = %s, verified %v, %v", describe(entries), verified, err)
	}
	// A changed byte fails the digest; a truncated or extended store is refused.
	tampered := bytes.Clone(data)
	tampered[len(tampered)/2] ^= 0x01
	if _, verified, _ := JCEKSEntries(tampered, [][]byte{[]byte("changeit")}); verified {
		t.Fatal("a tampered store verified")
	}
	for name, bad := range map[string][]byte{
		"truncated": data[:len(data)-40],
		"extended":  append(bytes.Clone(data[:len(data)-20]), append([]byte{0}, data[len(data)-20:]...)...),
	} {
		if _, _, err := JCEKSEntries(bad, [][]byte{[]byte("changeit")}); err == nil {
			t.Fatalf("a %s store was read", name)
		}
	}

	secrets, verified, err := JCEKSEntries(readFixture(t, x2l2SecretsOnly), [][]byte{[]byte("changeit")})
	if err != nil || !verified || describe(secrets) != "db.password=secret[] s3.secret.key=secret[]" {
		t.Fatalf("secret-only store = %s, verified %v, %v", describe(secrets), verified, err)
	}
}

// The serialization walk steps over exactly one object and refuses a stream
// that is not one: a missing header, a truncated object, or a reference to
// a handle that was never assigned.
func TestSkipSerializedObjectStepsOverOneSealedKeyX2L2(t *testing.T) {
	data := readFixture(t, x2l2SecretsOnly)
	start := bytes.Index(data, []byte{0xAC, 0xED, 0x00, 0x05})
	if start < 0 {
		t.Fatal("no serialized object in the fixture")
	}
	n, err := skipSerializedObject(data[start:])
	if err != nil {
		t.Fatal(err)
	}
	// The next entry's tag (3, a secret key) follows the object.
	if next := data[start+n : start+n+4]; !bytes.Equal(next, []byte{0, 0, 0, 3}) {
		t.Fatalf("after the object: % x; want the next entry's tag", next)
	}
	for name, bad := range map[string][]byte{
		"no header":      data[start+4 : start+n],
		"truncated":      data[start : start+n-1],
		"bad reference":  {0xAC, 0xED, 0x00, 0x05, tcReference, 0x00, 0x7E, 0x00, 0x09},
		"unknown marker": {0xAC, 0xED, 0x00, 0x05, 0x6F},
	} {
		if _, err := skipSerializedObject(bad); err == nil {
			t.Fatalf("%s: stepped over", name)
		}
	}
}
