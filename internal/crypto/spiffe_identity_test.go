// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"strings"
	"testing"
)

// These canonical wire identities follow SPIFFE-ID sections 2.1–2.4 and the
// stock go-spiffe strict parser. We reject noncanonical casing rather than
// silently normalizing a value used in an exact authorization comparison.
func TestParseSPIFFEIDCanonicalGrammar(t *testing.T) {
	valid := []string{
		"spiffe://example.org", "spiffe://example.org/ns/default/sa/web",
		"spiffe://trust_domain-1.example/Agent_2/v1.0", "spiffe://127.0.0.1/a",
		"spiffe://example.org/...", "spiffe://" + strings.Repeat("a", 255) + "/a",
		"spiffe://example.org/" + strings.Repeat("a", 2048-len("spiffe://example.org/")),
	}
	for _, id := range valid {
		u, err := ParseSPIFFEID(id)
		if err != nil || u.String() != id {
			t.Errorf("valid canonical identity was changed or rejected: %q, %v", id, err)
		}
	}
	invalid := []string{
		"", "https://example.org/a", "SPIFFE://example.org/a", "spiffe:/example.org/a",
		"spiffe:///a", "spiffe://EXAMPLE.org/a", "spiffe://example.org:443/a",
		"spiffe://user@example.org/a", "spiffe://[::1]/a", "spiffe://exa%6dple.org/a",
		"spiffe://example.org/", "spiffe://example.org//a", "spiffe://example.org/a/",
		"spiffe://example.org/a//b", "spiffe://example.org/.", "spiffe://example.org/a/../b",
		"spiffe://example.org/a/./b", "spiffe://example.org/a%2Fb", "spiffe://example.org/%61",
		"spiffe://example.org/a:b", "spiffe://example.org/a@b", "spiffe://example.org/a~b",
		"spiffe://example.org/a?", "spiffe://example.org/a#", "spiffe://example.org/a?q=1",
		"spiffe://example.org/a#b", "spiffe://example.org/é", "spiffe://é.example/a",
		"spiffe://example.org/a b", "spiffe://example.org/a\\b", "spiffe://example.org/a\x00b",
		" spiffe://example.org/a", "spiffe://example.org/a\n",
		"spiffe://" + strings.Repeat("a", 256) + "/a",
		"spiffe://example.org/" + strings.Repeat("a", 2049-len("spiffe://example.org/")),
	}
	for _, id := range invalid {
		if _, err := ParseSPIFFEID(id); err == nil {
			t.Errorf("accepted noncanonical or invalid identity: %q", id)
		}
	}
}

func TestParseSPIFFEIDEveryASCIICharacter(t *testing.T) {
	for ch := 0; ch < 128; ch++ {
		c := byte(ch)
		pathAllowed := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune(".-_", rune(c))
		for _, component := range []string{"trust-domain", "path"} {
			allowed := pathAllowed
			id := "spiffe://example.org/a" + string(c) + "b"
			if component == "trust-domain" {
				allowed = pathAllowed && (c < 'A' || c > 'Z')
				id = "spiffe://a" + string(c) + "b.example/c"
			}
			// A slash changes components/segments rather than appearing inside one.
			// Explicit grammar cases cover separators and empty segments.
			if c == '/' {
				continue
			}
			_, err := ParseSPIFFEID(id)
			if (err == nil) != allowed {
				t.Errorf("%s accepted=%v for ASCII %d, want %v", component, err == nil, ch, allowed)
			}
		}
	}
}
