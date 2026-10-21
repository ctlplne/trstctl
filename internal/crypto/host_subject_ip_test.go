// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"net"
	"testing"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// Host subject CSRs built from a template carry iPAddress SANs (A35).
func TestHostSubjectCSRsCarryTemplateIPAddresses(t *testing.T) {
	t.Parallel()
	tmpl := CertificateRequestTemplate{
		CommonName: "api.example.test", DNSNames: []string{"api.example.test"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.7"), net.ParseIP("2001:db8::1")},
	}
	key, err := GenerateHostSubjectKeyFromTemplate(tmpl)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	info, err := InspectCSR(key.CSRDER)
	if err != nil || len(info.IPAddresses) != 2 || info.IPAddresses[0] != "10.0.0.7" || info.IPAddresses[1] != "2001:db8::1" {
		t.Fatalf("generated CSR IPs = %v (%v); want both template addresses", info.IPAddresses, err)
	}
	if _, err := GenerateHostSubjectKeyFromTemplate(CertificateRequestTemplate{}); err == nil {
		t.Fatal("a template naming nothing produced a key")
	}

	retained, err := GenerateLockedKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer retained.Destroy()
	privatePEM, err := retained.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(privatePEM)
	csr, err := CreateRetainedHostKeyCSRFromTemplate(privatePEM, tmpl, SHA256Hex(retained.Public().DER))
	if err != nil {
		t.Fatal(err)
	}
	info, err = InspectCSR(csr)
	if err != nil || len(info.IPAddresses) != 2 || len(info.DNSNames) != 1 {
		t.Fatalf("retained-key CSR identifiers dns=%v ip=%v (%v)", info.DNSNames, info.IPAddresses, err)
	}
}
