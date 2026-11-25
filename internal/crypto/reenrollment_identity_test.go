// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"
)

func TestReenrollmentBindsSubjectAndMailbox(t *testing.T) {
	ca, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.Destroy)
	caDER, err := SelfSignedCACert(ca, "test enrollment CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	request := func(team, mailbox string, dns []string) []byte {
		t.Helper()
		key, err := GenerateLockedKey(ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		defer key.Destroy()
		signer, err := newX509Signer(key)
		if err != nil {
			t.Fatal(err)
		}
		san, err := subjectAltNameWithMailboxes(false, dns, nil, nil, nil, []string{mailbox})
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject:         pkix.Name{CommonName: "printer", OrganizationalUnit: []string{team}},
			ExtraExtensions: []pkix.Extension{san},
		}, signer)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	names := []string{"printer.example.test", "print.example.test"}
	const mailbox = "renée@example.test"
	first := request("Accounts", mailbox, names)
	certDER, err := SignLeafFromCSR(caDER, ca, first, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	for _, tc := range []struct {
		name         string
		request      []byte
		estOK, cmpOK bool
	}{
		{"rekey", request("Accounts", mailbox, names), true, true},
		{"reordered SANs", request("Accounts", mailbox, []string{names[1], names[0]}), true, true},
		{"different department", request("Shipping", mailbox, names), false, false},
		{"different mailbox", request("Accounts", "noël@example.test", names), false, false},
		{"one fewer DNS name", request("Accounts", mailbox, names[:1]), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := CSRBoundToTLSClientIdentity(state, tc.request); (err == nil) != tc.estOK || err != nil && !errors.Is(err, ErrCSRNotBoundToIdentity) {
				t.Errorf("EST identity binding = %v, want accepted=%v", err, tc.estOK)
			}
			for _, inspector := range []func([]byte) (CSRInfo, error){nil, InspectCSR} {
				if err := csrBoundToProtectionIdentity(tc.request, inspector, cert); (err == nil) != tc.cmpOK || err != nil && !errors.Is(err, ErrCMPCSRNotBound) {
					t.Errorf("CMP identity binding (inspector=%v) = %v, want accepted=%v", inspector != nil, err, tc.cmpOK)
				}
			}
		})
	}
}

func FuzzEnrollmentSANs(f *testing.F) {
	f.Add([]byte{0x30, 0x03, 0x82, 0x01, 'a'})
	f.Add([]byte{0x30, 0x0c, 0x87, 0x04, 127, 0, 0, 1, 0x87, 0x04, 127, 0, 0, 1})
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, der []byte) {
		names, err := enrollmentSANs(der)
		if err == nil && len(der) > 0 && len(names) == 0 {
			t.Fatal("nonempty SAN extension accepted without a name")
		}
	})
}
