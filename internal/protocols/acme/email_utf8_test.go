// SPDX-License-Identifier: BUSL-1.1

package acme

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
)

// P15-L4 part 2: a mailbox's local part may hold non-ASCII characters (RFC
// 6531), kept exactly as written — never case-folded and never normalized —
// while its domain is kept in A-labels. A control character, a byte order
// mark or bytes that are not UTF-8 are refused. Such a mailbox is requested
// as an SmtpUTF8Mailbox in its comparable form; an ASCII mailbox never is.
func TestEmailIdentifiersTakeNonASCIILocalPartsP15L4(t *testing.T) {
	decomposed := "a" + string(rune(0x030A)) + "lice@p15l4.test"
	for in, want := range map[string]string{
		"ålice@p15l4.test":         "ålice@p15l4.test",
		"Ålice@P15L4.test":         "Ålice@p15l4.test",
		"ålice@bücher.p15l4.test":  "ålice@xn--bcher-kva.p15l4.test",
		`"ålice smith"@p15l4.test`: `"ålice smith"@p15l4.test`,
		decomposed:                 decomposed,
	} {
		got, err := NormalizeEmailIdentifier(in)
		if err != nil || got != want {
			t.Fatalf("NormalizeEmailIdentifier(%q) = %q %v, want %q", in, got, err, want)
		}
	}
	if precomposed, _ := NormalizeEmailIdentifier("ålice@p15l4.test"); precomposed == decomposed {
		t.Fatal("a decomposed local part was normalized")
	}
	for _, bad := range []string{"ålice" + string(rune(0x85)) + "@p15l4.test", string(rune(0xFEFF)) + "alice@p15l4.test",
		"\xff\xfe@p15l4.test", "å*@p15l4.test"} {
		if got, err := NormalizeEmailIdentifier(bad); err == nil {
			t.Fatalf("NormalizeEmailIdentifier(%q) = %q, want a refusal", bad, got)
		}
	}

	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	ku, err := crypto.KeyUsageRequestExtension(true, false, false)
	if err != nil {
		t.Fatal(err)
	}
	csr := func(rfc822, mailboxes []string) []byte {
		t.Helper()
		der, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{EmailAddresses: rfc822, SmtpUTF8Mailboxes: mailboxes,
			ExtraExtensions: []crypto.CertificateExtension{ku}}, key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	if err := csrEmailIdentifiersMatchOrder(csr(nil, []string{"ålice@p15l4.test"}), []string{"ålice@p15l4.test"}); err != nil {
		t.Fatalf("an SmtpUTF8Mailbox for the order's mailbox: %v", err)
	}
	for name, tc := range map[string]struct {
		rfc822, mailboxes, authorized []string
		want                          string
	}{
		"an ASCII mailbox as an SmtpUTF8Mailbox": {nil, []string{"bob@p15l4.test"}, []string{"bob@p15l4.test"}, "RFC 9598 requires an rfc822Name"},
		"a U-label domain":                       {nil, []string{"ålice@bücher.p15l4.test"}, []string{"ålice@xn--bcher-kva.p15l4.test"}, "A-label form"},
		"another mailbox":                        {nil, []string{"Ålice@p15l4.test"}, []string{"ålice@p15l4.test"}, "did not authorize"},
		"the mailbox left out":                   {[]string{"bob@p15l4.test"}, nil, []string{"bob@p15l4.test", "ålice@p15l4.test"}, "omits"},
	} {
		err := csrEmailIdentifiersMatchOrder(csr(tc.rfc822, tc.mailboxes), tc.authorized)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: %v, want %q", name, err, tc.want)
		}
	}
}
