// SPDX-License-Identifier: BUSL-1.1

package keyposture

import (
	"encoding/pem"
	"os"
	"strings"
	"testing"
)

func fixtureDER(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name) // #nosec G304 -- a fixed test fixture directory, named by the test itself (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("%s holds no certificate", name)
	}
	return block.Bytes
}

// The real EM OV TLS CA - G3C intermediate is weak (its P-384 private key is
// 4) and is itself on the distrust list; a leaf under it is distrusted by its
// authority key identifier, or by its recorded chain when one was kept.
func TestRateCertificateFindsWeakKeysAndDistrustedIssuers(t *testing.T) {
	inter := fixtureDER(t, "em-ov-tls-ca-g3c.pem")
	v, err := RateCertificate(inter, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Weak() || !strings.Contains(v.WeakReasons[0], "its private key is 4") || v.DistrustEntry != "EM OV TLS CA - G3C" || v.DistrustHow != "itself" || v.RiskFloor() != RiskDistrusted {
		t.Fatalf("intermediate: %+v", v)
	}
	leaf := fixtureDER(t, "leaf-under-em-ov-tls-ca-g3c.pem")
	v, err = RateCertificate(leaf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v.Weak() || v.DistrustEntry != "EM OV TLS CA - G3C" || v.DistrustHow != "issuer_key_id" || !strings.Contains(v.DistrustReason, "4*G") {
		t.Fatalf("leaf by key identifier: %+v", v)
	}
	if v, err = RateCertificate(leaf, [][]byte{inter}); err != nil || v.DistrustHow != "chain" {
		t.Fatalf("leaf with its chain: %+v %v", v, err)
	}
	if _, err := RateCertificate([]byte("junk"), nil); err == nil {
		t.Fatal("garbage rated without error")
	}
	// A PEM bundle: the first certificate is rated, the rest is its chain.
	bundle := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: inter})...)
	if v, err := RateCertificateBytes(bundle); err != nil || v.DistrustHow != "chain" || v.Weak() {
		t.Fatalf("PEM bundle: %+v %v", v, err)
	}
	if v, err := RateCertificateBytes(inter); err != nil || v.DistrustHow != "itself" {
		t.Fatalf("DER bytes: %+v %v", v, err)
	}
	if _, err := RateCertificateBytes([]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")); err == nil {
		t.Fatal("a PEM input without a certificate was rated")
	}
}

// An inventory row that kept no certificate bytes is rated from what it
// recorded: its key-algorithm name and its issuer's common name.
func TestRateRecordedUsesTheIssuerNameAndAlgorithmName(t *testing.T) {
	v := RateRecorded(`CN=EM OV TLS CA - G3C,O=eMudhra Inc,C=US`, "ECDSA")
	if v.Weak() || v.DistrustEntry != "EM OV TLS CA - G3C" || v.DistrustHow != DistrustedByName {
		t.Fatalf("issuer name: %+v", v)
	}
	if v := RateRecorded("CN=Legacy CA", "RSA-1024"); !v.Weak() || v.Distrusted() || v.RiskFloor() != RiskWeak {
		t.Fatalf("RSA-1024: %+v", v)
	}
	if v := RateRecorded("CN=Legacy CA", "ECDSA"); !v.Empty() || v.RiskFloor() != 0 {
		t.Fatalf("an ECDSA row with an ordinary issuer: %+v", v)
	}
}

func TestVerdictMetadataRoundTrips(t *testing.T) {
	in := Verdict{WeakReasons: []string{"RSA-1024 is below the 2048-bit minimum", "the RSA modulus is divisible by 3"}, DistrustEntry: "EM OV TLS CA - G3C", DistrustHow: "issuer_key_id", DistrustReason: "weak keys", DistrustSubject: "CN=EM OV TLS CA - G3C"}
	strs := in.StringMetadata()
	if strs[MetaKeyStrength] != "weak" {
		t.Fatalf("string metadata = %+v", strs)
	}
	if out := FromStringMetadata(strs); strings.Join(out.WeakReasons, "|") != strings.Join(in.WeakReasons, "|") || out.DistrustEntry != in.DistrustEntry || out.DistrustHow != in.DistrustHow {
		t.Fatalf("round trip = %+v", out)
	}
	meta := map[string]any{"subject": "CN=x"}
	in.AddTo(meta)
	if out := FromMetadata(meta); out.DistrustSubject != in.DistrustSubject || len(out.WeakReasons) != 2 {
		t.Fatalf("any round trip = %+v", out)
	}
	if out := FromMetadata(map[string]any{"key_strength": "weak"}); !out.Weak() {
		t.Fatal("a weak mark without a reason was lost")
	}
	if !FromMetadata(map[string]any{}).Empty() || len((Verdict{}).StringMetadata()) != 0 {
		t.Fatal("an empty verdict wrote metadata")
	}
}

func TestCommonNameHonoursEscapes(t *testing.T) {
	for dn, want := range map[string]string{
		`CN=EM OV TLS CA - G3C,O=eMudhra Inc,C=US`: "EM OV TLS CA - G3C",
		`O=Acme\, Inc.,CN=Acme Issuing CA\, Two`:   "Acme Issuing CA, Two",
		`C=US,O=Nobody`:                            "",
		`cn=lower case`:                            "lower case",
	} {
		if got := CommonName(dn); got != want {
			t.Fatalf("CommonName(%q) = %q, want %q", dn, got, want)
		}
	}
}
