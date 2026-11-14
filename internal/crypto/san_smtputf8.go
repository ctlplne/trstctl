// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net"
	"net/url"

	"trstctl.com/trstctl/internal/crypto/certinfo"
)

var oidSubjectAltNameExt = asn1.ObjectIdentifier{2, 5, 29, 17}

func ia5(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// subjectAltNameWithMailboxes encodes a subjectAltName holding the names the
// x509 encoder would write (dNSName, rfc822Name, iPAddress, URI, in its
// order) followed by each internationalized mailbox as an SmtpUTF8Mailbox
// otherName (RFC 9598 §3; P15-L4), which the x509 encoder cannot write. The
// extension is critical when the subject is empty (RFC 5280 §4.2.1.6).
func subjectAltNameWithMailboxes(subjectEmpty bool, dns, emails []string, ips []net.IP, uris []*url.URL, mailboxes []string) (pkix.Extension, error) {
	var names []asn1.RawValue
	add := func(tag int, value string) error {
		if !ia5(value) {
			return errors.New("crypto: a dNSName, rfc822Name or URI must be ASCII; an internationalized mailbox is an SmtpUTF8Mailbox")
		}
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, Bytes: []byte(value)})
		return nil
	}
	for _, name := range dns {
		if err := add(2, name); err != nil {
			return pkix.Extension{}, err
		}
	}
	for _, email := range emails {
		if err := add(1, email); err != nil {
			return pkix.Extension{}, err
		}
	}
	for _, ip := range ips {
		raw := ip.To4()
		if raw == nil {
			raw = ip.To16()
		}
		if raw == nil {
			return pkix.Extension{}, errors.New("crypto: an iPAddress SAN is malformed")
		}
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 7, Bytes: append([]byte(nil), raw...)})
	}
	for _, uri := range uris {
		if err := add(6, uri.String()); err != nil {
			return pkix.Extension{}, err
		}
	}
	oid, err := asn1.Marshal(certinfo.OIDSmtpUTF8Mailbox)
	if err != nil {
		return pkix.Extension{}, err
	}
	for _, mailbox := range mailboxes {
		value, err := asn1.MarshalWithParams(mailbox, "utf8")
		if err != nil {
			return pkix.Extension{}, err
		}
		explicit, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: value})
		if err != nil {
			return pkix.Extension{}, err
		}
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
			Bytes: append(append([]byte(nil), oid...), explicit...)})
	}
	der, err := asn1.Marshal(names)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{Id: oidSubjectAltNameExt, Critical: subjectEmpty, Value: der}, nil
}
