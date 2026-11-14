// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/x509"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// P15-L4 part 2: a mailbox with a non-ASCII local part travels as an
// SmtpUTF8Mailbox otherName (RFC 9598) from the CSR into the leaf, beside
// the CSR's other names, and the leaf profile polices it with the
// rfc822Names: a mail domain the profile does not permit is refused.
func TestSmtpUTF8MailboxRoundTripsThroughCSRAndLeafP15L4(t *testing.T) {
	ca, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Destroy()
	caDER, err := SelfSignedCACert(ca, "p15l4 test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	csr, err := CreateCertificateRequest(CertificateRequestTemplate{EmailAddresses: []string{"bob@p15l4.test"},
		SmtpUTF8Mailboxes: []string{"ålice@p15l4.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := CSRRequestedIdentifiers(csr)
	if err != nil || len(ids.SmtpUTF8Mailboxes) != 1 || ids.SmtpUTF8Mailboxes[0] != "ålice@p15l4.test" ||
		len(ids.EmailAddresses) != 1 || ids.EmailAddresses[0] != "bob@p15l4.test" {
		t.Fatalf("the CSR's identifiers = %+v %v", ids, err)
	}
	info, err := InspectCSR(csr)
	if err != nil || len(info.EmailAddresses) != 2 || info.EmailAddresses[1] != "ålice@p15l4.test" || len(info.SmtpUTF8Mailboxes) != 1 {
		t.Fatalf("InspectCSR = %+v %v; want both mailboxes policed as email", info, err)
	}
	leafDER, err := SignLeafFromCSRWithProfile(caDER, ca, csr, time.Hour, LeafProfile{PermittedEmailDomains: []string{"p15l4.test"}})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	mailboxes, err := certinfo.SmtpUTF8Mailboxes(leaf.Extensions)
	if err != nil || len(mailboxes) != 1 || mailboxes[0] != "ålice@p15l4.test" || len(leaf.EmailAddresses) != 1 || leaf.EmailAddresses[0] != "bob@p15l4.test" {
		t.Fatalf("the leaf names %v and SmtpUTF8Mailbox %v (%v)", leaf.EmailAddresses, mailboxes, err)
	}
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(oidSubjectAltNameExt) && !ext.Critical {
			t.Fatal("the subjectAltName of a leaf with an empty subject is not critical")
		}
	}
	shown, err := certinfo.Inspect(leafDER)
	if err != nil || len(shown.SmtpUTF8Mailboxes) != 1 || shown.SmtpUTF8Mailboxes[0] != "ålice@p15l4.test" {
		t.Fatalf("certinfo = %+v %v", shown.SmtpUTF8Mailboxes, err)
	}
	if _, err := SignLeafFromCSRWithProfile(caDER, ca, csr, time.Hour, LeafProfile{PermittedEmailDomains: []string{"other.test"}}); err == nil {
		t.Fatal("a profile that does not permit the SmtpUTF8Mailbox's domain issued it")
	}
	if _, err := subjectAltNameWithMailboxes(true, nil, []string{"ålice@p15l4.test"}, nil, nil, nil); err == nil {
		t.Fatal("a non-ASCII rfc822Name was encoded")
	}
}
