// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestLdapPasswordDecodesWithoutAStringIntermediate is the regression guard for
// the AN-8 gap that hid inside a correct-looking wipe().
//
// UnmarshalJSON used to decode into a Go string and then copy to []byte. wipe()
// zeroes the slice carefully — loop plus runtime.KeepAlive — but it cannot reach
// that string: Go strings are immutable, so the password stayed on the heap until
// the GC happened to collect it. The type exists precisely to keep credential
// material byte-backed and zeroable, and the intermediate string is the one thing
// that defeats it.
//
// A test cannot observe heap residue directly, so this pins the decode contract
// instead: the bytes must round-trip exactly, and wipe() must leave nothing.
func TestLdapPasswordDecodesWithoutAStringIntermediate(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
		want string
	}{
		{"plain", `"hunter2"`, "hunter2"},
		{"quote escape", `"a\"b"`, `a"b`},
		{"backslash", `"a\\b"`, `a\b`},
		{"solidus", `"a\/b"`, "a/b"},
		{"control escapes", `"a\tb\nc\rd\be\ff"`, "a\tb\nc\rd\be\ff"},
		{"unicode escape", `"café"`, "café"},
		{"surrogate pair", `"😀"`, "😀"},
		{"multibyte literal", `"пароль→世界"`, "пароль→世界"},
		{"empty", `""`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var p ldapPassword
			if err := json.Unmarshal([]byte(tc.json), &p); err != nil {
				t.Fatalf("unmarshal %s: %v", tc.json, err)
			}
			if string(p) != tc.want {
				t.Fatalf("decoded %q, want %q", string(p), tc.want)
			}

			// The whole point: what was decoded is addressable and can be zeroed.
			p.wipe()
			for i, b := range p {
				if b != 0 {
					t.Fatalf("byte %d survived wipe() as %#x; the password is still in memory", i, b)
				}
			}
		})
	}
}

// TestLdapPasswordMatchesEncodingJSON pins the decoder against the standard
// library for the same inputs, so replacing json.Unmarshal did not quietly
// change which passwords are accepted or how they decode.
func TestLdapPasswordMatchesEncodingJSON(t *testing.T) {
	for _, raw := range []string{
		`"hunter2"`, `"a\"b"`, `"a\\b"`, `"a\/b"`, `"\t\n\r\b\f"`,
		`"café"`, `"😀"`, `"пароль→世界"`, `""`, `"  spaced  "`,
		`"\u0000nul"`, `"\u00e9"`, `"\ud83d\ude00"`,
	} {
		var want string
		if err := json.Unmarshal([]byte(raw), &want); err != nil {
			t.Fatalf("fixture %s is not valid JSON: %v", raw, err)
		}
		var got ldapPassword
		if err := json.Unmarshal([]byte(raw), &got); err != nil {
			t.Fatalf("ldapPassword rejected %s which encoding/json accepts: %v", raw, err)
		}
		if string(got) != want {
			t.Errorf("%s decoded to %q, encoding/json gives %q", raw, string(got), want)
		}
	}
}

// TestLdapPasswordRejectsNonStrings keeps the decoder strict: a number or object
// where a password belongs is a malformed request, not an empty password.
func TestLdapPasswordRejectsNonStrings(t *testing.T) {
	for _, raw := range []string{`123`, `{"a":1}`, `[]`, `true`, `"unterminated`} {
		var p ldapPassword
		if err := json.Unmarshal([]byte(raw), &p); err == nil {
			t.Errorf("%s was accepted as a password and decoded to %q", raw, string(p))
		}
	}
	// null is the one non-string that is meaningful: no password supplied.
	var p ldapPassword
	if err := json.Unmarshal([]byte(`null`), &p); err != nil {
		t.Errorf("null password rejected: %v", err)
	}
	if len(p) != 0 {
		t.Errorf("null decoded to %q, want empty", string(p))
	}
}

// TestLdapPasswordDecodeDoesNotReallocate is the AN-8 realloc guard for
// AUD-201 follow-up I2/V14, mirroring
// TestMongoCommandDoesNotReallocateAfterThePassword. The previous hand-rolled
// decoder grew its output from a cap-0 slice, so a 100-byte password left
// abandoned 8/16/32/64-byte prefix arrays on the heap that wipe() can never
// reach. The shared secretjson decoder preallocates once: the decoded buffer's
// capacity equals the source length minus the quotes, which is only possible
// with a single backing array from start to finish.
func TestLdapPasswordDecodeDoesNotReallocate(t *testing.T) {
	password := strings.Repeat("p", 100)
	raw := []byte(`"` + password + `"`)
	var p ldapPassword
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if string(p) != password {
		t.Fatalf("decoded %q, want the fixture password", string(p))
	}
	if cap(p) != len(raw)-2 {
		t.Fatalf("decoded buffer cap = %d, want %d (a single preallocated array); "+
			"growth reallocations abandon unwipeable prefix copies of the password on the heap",
			cap(p), len(raw)-2)
	}
}

// TestLdapPasswordRejectsControlBytesAndMalformedSurrogates pins the strict
// behaviour AUD-201 follow-up I2/V24 adopted with the shared decoder. The
// bespoke copy had diverged: it accepted unescaped control bytes and folded
// lone or invalid surrogates to U+FFFD — lossy for a bind credential, since
// two malformed inputs decoded to the same password bytes.
func TestLdapPasswordRejectsControlBytesAndMalformedSurrogates(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"unescaped control byte", []byte("\"pass\x01word\"")},
		{"lone high surrogate", []byte(`"\ud800"`)},
		{"lone low surrogate", []byte(`"\ude00"`)},
		{"invalid surrogate pair", []byte(`"\ud800\ud800"`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var p ldapPassword
			if err := json.Unmarshal(tc.raw, &p); err == nil {
				t.Fatalf("%s was accepted and decoded to %q; two malformed inputs must not alias one password", tc.name, string(p))
			}
		})
	}
}
