// SPDX-License-Identifier: BUSL-1.1

package jose

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Q3-L1 Done-when: a CycloneDX CBOM carries its own enveloped JSF signature
// (jsf-0.82, RS256) over the RFC 8785 canonical form of the BOM, so the BOM
// alone verifies after any reformatting with the pinned audit evidence keys;
// a changed BOM, another key, or an embedded public key that is not the
// pinned key fail.

// RFC 8785 §3.2.2 (the canonical form of its sample document), §3.2.3 (sort
// by UTF-16 code units) and Appendix B (number serialization). Node's
// JSON.stringify, which RFC 8785 is defined by, gives the same strings.
func TestCanonicalizeMatchesRFC8785Q3L1(t *testing.T) {
	sample := `{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}`
	got, err := Canonicalize([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`; string(got) != want {
		t.Fatalf("canonical form\n got %s\nwant %s", got, want)
	}

	sorting := `{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One",` +
		`"\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}`
	got, err = Canonicalize([]byte(sorting))
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"\u00f6\":\"Latin Small Letter O With Diaeresis\"," +
		"\"\u20ac\":\"Euro Sign\",\"\U0001F600\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}"; string(got) != want {
		t.Fatalf("sorted by UTF-16 code units\n got %s\nwant %s", got, want)
	}

	for bits, want := range map[string]string{
		"0000000000000000": "0", "8000000000000000": "0", "0000000000000001": "5e-324", "8000000000000001": "-5e-324",
		"7fefffffffffffff": "1.7976931348623157e+308", "ffefffffffffffff": "-1.7976931348623157e+308",
		"4340000000000000": "9007199254740992", "c340000000000000": "-9007199254740992",
		"4430000000000000": "295147905179352830000", "44b52d02c7e14af5": "9.999999999999997e+22",
		"44b52d02c7e14af6": "1e+23", "44b52d02c7e14af7": "1.0000000000000001e+23",
		"444b1ae4d6e2ef4e": "999999999999999700000", "444b1ae4d6e2ef4f": "999999999999999900000",
		"444b1ae4d6e2ef50": "1e+21", "3eb0c6f7a0b5ed8c": "9.999999999999997e-7", "3eb0c6f7a0b5ed8d": "0.000001",
		"41b3de4355555553": "333333333.3333332", "41b3de4355555554": "333333333.33333325",
		"41b3de4355555555": "333333333.3333333", "41b3de4355555556": "333333333.3333334",
		"41b3de4355555557": "333333333.33333343", "becbf647612f3696": "-0.0000033333333333333333",
		"43143ff3c1cb0959": "1424953923781206.2",
	} {
		raw, err := hex.DecodeString(bits)
		if err != nil {
			t.Fatal(err)
		}
		f := math.Float64frombits(binary.BigEndian.Uint64(raw))
		text, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Canonicalize(text)
		if err != nil || string(got) != want {
			t.Fatalf("number %s (%s) = %s %v, want %s", bits, text, got, err, want)
		}
	}

	// Not I-JSON: refused, never normalized.
	for name, doc := range map[string]string{
		"repeated member":            `{"a":1,"a":2}`,
		"repeated member by escape":  `{"a":1,"a":2}`,
		"lone high surrogate":        `{"a":"\ud83d"}`,
		"high surrogate then letter": `{"a":"\ud83dx"}`,
		"lone low surrogate":         `{"a":"\ude00"}`,
		"invalid UTF-8":              "{\"a\":\"\xff\"}",
		"data after the document":    `{"a":1} {"b":2}`,
		"number beyond a double":     `{"a":1e400}`,
		"nesting beyond the bound":   strings.Repeat("[", maxJCSDepth+2) + strings.Repeat("]", maxJCSDepth+2),
		"truncated":                  `{"a":`,
	} {
		if got, err := Canonicalize([]byte(doc)); err == nil {
			t.Fatalf("%s: canonicalized %q to %s, want a refusal", name, doc, got)
		}
	}
	// An escaped backslash before "ud83d" is text, not an escape.
	if got, err := Canonicalize([]byte(`{"a":"\\ud83d"}`)); err != nil || string(got) != `{"a":"\\ud83d"}` {
		t.Fatalf("escaped backslash = %s %v", got, err)
	}
}

func signedTestBOM(t *testing.T, key *SigningKey, bom map[string]any) []byte {
	t.Helper()
	jwks, err := key.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	template, err := JSFTemplateFromJWKS(jwks)
	if err != nil {
		t.Fatal(err)
	}
	bom["signature"] = template
	unsigned, err := json.Marshal(bom)
	if err != nil {
		t.Fatal(err)
	}
	value, err := key.SignArtifact(ArtifactCBOMCycloneDXJSF, unsigned)
	if err != nil {
		t.Fatal(err)
	}
	template.Value = value
	bom["signature"] = template
	signed, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func readTestBOM(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "cbom", "testdata", name)) // #nosec G304 -- the repository's own fixture (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	var bom map[string]any
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatal(err)
	}
	return bom
}

func reformat(t *testing.T, doc []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(doc, &v); err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(v)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestJSFSignedBOMVerifiesAfterReformattingQ3L1(t *testing.T) {
	key, err := GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	other, err := GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	signed := signedTestBOM(t, key, readTestBOM(t, "cyclonedx-export-supplement.golden.json"))
	if kid, err := key.JWKS().VerifyJSF(signed); err != nil || kid != "audit-export" {
		t.Fatalf("verify the signed BOM = %q %v", kid, err)
	}
	// Reformatted (compact, members in another order): still verifies.
	if _, err := key.JWKS().VerifyJSF(reformat(t, signed, nil)); err != nil {
		t.Fatalf("verify the reformatted BOM: %v", err)
	}
	// A changed component fails.
	changed := reformat(t, signed, func(v map[string]any) {
		v["components"].([]any)[0].(map[string]any)["name"] = "RSA-4096"
	})
	if _, err := key.JWKS().VerifyJSF(changed); err == nil {
		t.Fatal("a changed BOM verified")
	}
	// Another key under the same kid fails.
	if _, err := other.JWKS().VerifyJSF(signed); err == nil {
		t.Fatal("the BOM verified with another key")
	}
	// Re-signed by another key that embeds its own public key: the pinned set
	// refuses it, because the BOM's public key is never trusted alone.
	forged := signedTestBOM(t, other, readTestBOM(t, "cyclonedx-export-supplement.golden.json"))
	if _, err := other.JWKS().VerifyJSF(forged); err != nil {
		t.Fatalf("the other key's own BOM: %v", err)
	}
	if _, err := key.JWKS().VerifyJSF(forged); err == nil {
		t.Fatal("a BOM signed by another key verified with the pinned key")
	}
	// A signature that excludes members is refused, as is a value whose
	// base64url spelling carries padding.
	excluded := reformat(t, signed, func(v map[string]any) {
		v["signature"].(map[string]any)["excludes"] = []any{"components"}
	})
	if _, err := key.JWKS().VerifyJSF(excluded); err == nil || !strings.Contains(err.Error(), "excludes") {
		t.Fatalf("excludes = %v", err)
	}
	padded := reformat(t, signed, func(v map[string]any) {
		sig := v["signature"].(map[string]any)
		sig["value"] = sig["value"].(string) + "=="
	})
	if _, err := key.JWKS().VerifyJSF(padded); err == nil {
		t.Fatal("a padded signature value verified")
	}

	// The signer admits only a CycloneDX BOM whose signature object names its
	// own key and holds no value.
	jwks, err := key.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	template, err := JSFTemplateFromJWKS(jwks)
	if err != nil {
		t.Fatal(err)
	}
	otherJWKS, err := other.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	otherTemplate, err := JSFTemplateFromJWKS(otherJWKS)
	if err != nil {
		t.Fatal(err)
	}
	for name, sig := range map[string]any{
		"another kid":       JSFSignature{Algorithm: "RS256", KeyID: "someone-else", PublicKey: template.PublicKey},
		"another algorithm": JSFSignature{Algorithm: "PS256", KeyID: "audit-export", PublicKey: template.PublicKey},
		"another key":       otherTemplate,
		"already a value":   JSFSignature{Algorithm: "RS256", KeyID: "audit-export", Value: "AAAA"},
		"excludes":          map[string]any{"algorithm": "RS256", "keyId": "audit-export", "excludes": []string{"components"}},
	} {
		doc, err := json.Marshal(map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "signature": sig})
		if err != nil {
			t.Fatal(err)
		}
		if value, err := key.SignArtifact(ArtifactCBOMCycloneDXJSF, doc); err == nil {
			t.Fatalf("%s: signed %s as %q", name, doc, value)
		}
	}
	for name, doc := range map[string]string{
		"not a BOM":    `{"bomFormat":"SPDX","signature":{"algorithm":"RS256","keyId":"audit-export"}}`,
		"no signature": `{"bomFormat":"CycloneDX","specVersion":"1.6"}`,
		"a JWS input":  `eyJhbGciOiJSUzI1NiJ9.e30`,
	} {
		if value, err := key.SignArtifact(ArtifactCBOMCycloneDXJSF, []byte(doc)); err == nil {
			t.Fatalf("%s: signed %s as %q", name, doc, value)
		}
	}
}

// updateJSFGolden rewrites the signed CBOM golden the console suite verifies
// with an independent implementation (Node's JSON.stringify for RFC 8785 and
// OpenSSL through node:crypto for RS256).
var updateJSFGolden = flag.Bool("update-jsf-golden", false,
	"rewrite internal/cbom/testdata/cyclonedx-export-signed.golden.json and its JWK set")

func TestJSFSignedBOMGoldenVerifiesQ3L1(t *testing.T) {
	dir := filepath.Join("..", "..", "cbom", "testdata")
	bomPath, jwksPath := filepath.Join(dir, "cyclonedx-export-signed.golden.json"), filepath.Join(dir, "cyclonedx-export-signed.jwks.json")
	if *updateJSFGolden {
		key, err := GenerateRSASigningKey("audit-export")
		if err != nil {
			t.Fatal(err)
		}
		signed := signedTestBOM(t, key, readTestBOM(t, "cyclonedx-export-supplement.golden.json"))
		jwks, err := key.PublicJWKS()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(bomPath, append(signed, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(jwksPath, append(jwks, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	signed, err := os.ReadFile(bomPath) // #nosec G304 -- the repository's own fixture (CWE-22)
	if err != nil {
		t.Fatalf("read the signed golden (run with -update-jsf-golden): %v", err)
	}
	jwks, err := os.ReadFile(jwksPath) // #nosec G304 -- the repository's own fixture (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ParseJWKSet(jwks)
	if err != nil {
		t.Fatal(err)
	}
	if kid, err := keys.VerifyJSF(signed); err != nil || kid != "audit-export" {
		t.Fatalf("the signed golden = %q %v", kid, err)
	}
}

// FuzzCanonicalize: canonicalization never panics, and a canonical form is
// its own canonical form.
func FuzzCanonicalize(f *testing.F) {
	for _, seed := range []string{
		`{"b":[1,2.5e-7,1e21],"a":"\u00e9\ud83d\ude00","c":{"z":null,"y":true}}`,
		`{"a":"\ud83d"}`, `[1e400]`, `"\\ud83d"`, `{"a":1,"a":2}`, `{}`, `[]`, `0`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, doc []byte) {
		out, err := Canonicalize(doc)
		if err != nil {
			return
		}
		again, err := Canonicalize(out)
		if err != nil || !bytes.Equal(again, out) {
			t.Fatalf("canonical form %q is not stable: %q %v", out, again, err)
		}
	})
}

// FuzzVerifyJSF: a hostile BOM never panics the verifier and never verifies
// without the pinned key's signature.
func FuzzVerifyJSF(f *testing.F) {
	key, err := GenerateRSASigningKey("audit-export")
	if err != nil {
		f.Fatal(err)
		return
	}
	f.Add([]byte(`{"bomFormat":"CycloneDX","signature":{"algorithm":"RS256","keyId":"audit-export","value":"AAAA"}}`))
	f.Add([]byte(`{"bomFormat":"CycloneDX","signature":{"algorithm":"RS256","keyId":"audit-export","publicKey":{"kty":"RSA","n":"AQ","e":"AQAB"},"value":"AA"}}`))
	f.Add([]byte(`{"bomFormat":"CycloneDX","signature":{"signers":[]}}`))
	f.Fuzz(func(t *testing.T, doc []byte) {
		if _, err := key.JWKS().VerifyJSF(doc); err == nil {
			t.Fatalf("an unsigned document verified: %q", doc)
		}
	})
}
