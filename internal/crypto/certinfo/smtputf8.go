// SPDX-License-Identifier: BUSL-1.1

package certinfo

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"strings"
	"unicode/utf8"
)

// OIDSmtpUTF8Mailbox is id-on-SmtpUTF8Mailbox (RFC 9598 §3): the otherName
// that names a mailbox whose local part has non-ASCII characters.
var OIDSmtpUTF8Mailbox = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 9}

var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// SmtpUTF8Mailboxes returns the SmtpUTF8Mailbox otherNames of the
// subjectAltName among extensions (P15-L4), in order. The x509 parser skips
// every otherName; this reads only this one type and leaves the others as it
// does. A malformed SmtpUTF8Mailbox (not a UTF8String, not UTF-8, empty or
// carrying a byte order mark) is an error, never a silently dropped name.
func SmtpUTF8Mailboxes(extensions []pkix.Extension) ([]string, error) {
	var out []string
	for _, ext := range extensions {
		if !ext.Id.Equal(oidSubjectAltName) {
			continue
		}
		var names []asn1.RawValue
		if rest, err := asn1.Unmarshal(ext.Value, &names); err != nil || len(rest) != 0 {
			return nil, errors.New("certinfo: the subjectAltName does not parse")
		}
		for _, name := range names {
			// otherName is [0] IMPLICIT SEQUENCE { type-id, [0] EXPLICIT value }.
			if name.Class != asn1.ClassContextSpecific || name.Tag != 0 || !name.IsCompound {
				continue
			}
			var typeID asn1.ObjectIdentifier
			rest, err := asn1.Unmarshal(name.Bytes, &typeID)
			if err != nil {
				return nil, errors.New("certinfo: an otherName does not parse")
			}
			if !typeID.Equal(OIDSmtpUTF8Mailbox) {
				continue
			}
			var explicit, value asn1.RawValue
			if rest, err = asn1.Unmarshal(rest, &explicit); err != nil || len(rest) != 0 ||
				explicit.Class != asn1.ClassContextSpecific || explicit.Tag != 0 || !explicit.IsCompound {
				return nil, errors.New("certinfo: an SmtpUTF8Mailbox has no [0] value")
			}
			if rest, err = asn1.Unmarshal(explicit.Bytes, &value); err != nil || len(rest) != 0 ||
				value.Class != asn1.ClassUniversal || value.Tag != asn1.TagUTF8String {
				return nil, errors.New("certinfo: an SmtpUTF8Mailbox is not a UTF8String")
			}
			mailbox := string(value.Bytes)
			if mailbox == "" || !utf8.ValidString(mailbox) || strings.HasPrefix(mailbox, string(rune(0xFEFF))) {
				return nil, errors.New("certinfo: an SmtpUTF8Mailbox is empty, not UTF-8 or begins with a byte order mark")
			}
			out = append(out, mailbox)
		}
	}
	return out, nil
}
