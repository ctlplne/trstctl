// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/pqc"
)

// hostRenewSubjectKey adapts algorithm implementations to the same custody
// lifetime: retain the locked key while signing is pending, install, then wipe.
type hostRenewSubjectKey struct {
	CSRDER     []byte
	privatePEM func() ([]byte, error)
	destroy    func()
}

func (k *hostRenewSubjectKey) PrivateKeyPEM() ([]byte, error) { return k.privatePEM() }
func (k *hostRenewSubjectKey) Destroy()                       { k.destroy() }

// hostSubjectTemplate is the request a host-generated key will be certified
// for: the intent's common name, DNS names and IP addresses, and nothing else.
// An IP address the intent spells in a form net.ParseIP cannot read fails
// closed here, before any key exists, rather than being dropped from the CSR
// and leaving the renewed certificate narrower than the binding.
func hostSubjectTemplate(intent DeployIntent) (crypto.CertificateRequestTemplate, error) {
	tmpl := crypto.CertificateRequestTemplate{CommonName: intent.SubjectCommonName, DNSNames: intent.SubjectDNSNames}
	for _, raw := range intent.SubjectIPAddresses {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil {
			return tmpl, fmt.Errorf("relay: renewal intent carries an unparseable IP address %q; no key was generated", raw)
		}
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	}
	for _, raw := range intent.SubjectEmailAddresses {
		if raw = strings.TrimSpace(raw); raw != "" {
			tmpl.EmailAddresses = append(tmpl.EmailAddresses, raw)
		}
	}
	for _, raw := range intent.SubjectURIs {
		if raw = strings.TrimSpace(raw); raw != "" {
			tmpl.URIs = append(tmpl.URIs, raw)
		}
	}
	return tmpl, nil
}

func generateHostRenewSubjectKey(intent DeployIntent) (*hostRenewSubjectKey, error) {
	algorithm := strings.TrimSpace(intent.SubjectKeyAlgorithm)
	tmpl, err := hostSubjectTemplate(intent)
	if err != nil {
		return nil, err
	}
	if algorithm == "" || algorithm == string(crypto.ECDSAP256) {
		key, err := crypto.GenerateHostSubjectKeyFromTemplate(tmpl)
		if err != nil {
			return nil, err
		}
		return &hostRenewSubjectKey{CSRDER: key.CSRDER, privatePEM: key.PrivateKeyPEM, destroy: key.Destroy}, nil
	}
	switch crypto.Algorithm(algorithm) {
	case pqc.MLDSA44, pqc.MLDSA65, pqc.MLDSA87:
		key, err := pqc.GenerateHostMLDSASubjectKey(tmpl, crypto.Algorithm(algorithm))
		if err != nil {
			return nil, err
		}
		return &hostRenewSubjectKey{CSRDER: key.CSRDER, privatePEM: key.PrivateKeyPEM, destroy: key.Destroy}, nil
	default:
		return nil, errors.New("relay: requested host subject algorithm is unsupported; no other algorithm was selected")
	}
}
