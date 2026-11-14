// SPDX-License-Identifier: BUSL-1.1

package acme

import "testing"

// P15-L4 part 1: an email identifier may have a quoted local part and an
// internationalized domain. The comparable form keeps the local part exact
// (quoted only when it is not a dot-atom, with the fewest escapes) and the
// domain lowercase in A-labels; a wildcard is refused, quoted or not.
func TestEmailIdentifiersTakeQuotedLocalPartsAndInternationalDomainsP15L4(t *testing.T) {
	for in, want := range map[string]string{
		`"john doe"@p15l4.test`:          `"john doe"@p15l4.test`,
		`"john"@p15l4.test`:              `john@p15l4.test`,
		`"John.Doe"@P15L4.TEST`:          `John.Doe@p15l4.test`,
		`"a\"b"@p15l4.test`:              `"a\"b"@p15l4.test`,
		`"a\\b"@p15l4.test`:              `"a\\b"@p15l4.test`,
		`"a\bc"@p15l4.test`:              `abc@p15l4.test`,
		`"at@sign"@p15l4.test`:           `"at@sign"@p15l4.test`,
		"alice@bücher.p15l4.test":        "alice@xn--bcher-kva.p15l4.test",
		"alice@XN--BCHER-KVA.p15l4.test": "alice@xn--bcher-kva.p15l4.test",
		"Alice@Example.TEST":             "Alice@example.test",
	} {
		got, err := NormalizeEmailIdentifier(in)
		if err != nil || got != want {
			t.Fatalf("NormalizeEmailIdentifier(%q) = %q %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{`"unterminated@p15l4.test`, `"a*b"@p15l4.test`, "a*b@p15l4.test", "\"tab\x01\"@p15l4.test",
		`"bad\"@p15l4.test`, "john doe@p15l4.test", "a@b@p15l4.test", "alice@xn--a.p15l4.test", "alice@-bad.p15l4.test",
		`""@p15l4.test`} {
		if got, err := NormalizeEmailIdentifier(bad); err == nil {
			t.Fatalf("NormalizeEmailIdentifier(%q) = %q, want a refusal", bad, got)
		}
	}

	// A reply's From, parsed: the quoted local part comes back quoted, and a
	// U-label domain compares in A-labels.
	for header, want := range map[string]string{
		`"John Doe" <"john doe"@p15l4.test>`: `"john doe"@p15l4.test`,
		"alice@bücher.p15l4.test":            "alice@xn--bcher-kva.p15l4.test",
	} {
		parsed, err := ParseEmailReply([]byte("From: " + header + "\r\nSubject: Re: ACME: tok\r\nContent-Type: text/plain\r\n\r\n" +
			emailResponseBegin + "\r\nresp\r\n" + emailResponseEnd + "\r\n"))
		if err != nil {
			t.Fatalf("ParseEmailReply(From: %s): %v", header, err)
		}
		if got, err := NormalizeEmailIdentifier(parsed.From); err != nil || got != want {
			t.Fatalf("the reply from %s compares as %q %v, want %q", header, got, err, want)
		}
	}

	// An EAB mail scope written in either label form admits the mailbox in
	// either form.
	for _, entry := range []string{"@bücher.p15l4.test", "@xn--bcher-kva.p15l4.test"} {
		if err := ValidEABIdentifierEntry(entry); err != nil {
			t.Fatalf("entry %q: %v", entry, err)
		}
		policy := EABPolicy{AllowedIdentifiers: []string{entry}}
		for _, mailbox := range []string{"alice@bücher.p15l4.test", "alice@xn--bcher-kva.p15l4.test"} {
			if !policy.permits(mailbox) {
				t.Fatalf("entry %q refused %q", entry, mailbox)
			}
		}
	}
}
