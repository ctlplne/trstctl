// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"errors"
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

func generateHostRenewSubjectKey(intent DeployIntent) (*hostRenewSubjectKey, error) {
	algorithm := strings.TrimSpace(intent.SubjectKeyAlgorithm)
	if algorithm == "" || algorithm == string(crypto.ECDSAP256) {
		key, err := crypto.GenerateHostSubjectKey(intent.SubjectCommonName, intent.SubjectDNSNames)
		if err != nil {
			return nil, err
		}
		return &hostRenewSubjectKey{CSRDER: key.CSRDER, privatePEM: key.PrivateKeyPEM, destroy: key.Destroy}, nil
	}
	switch crypto.Algorithm(algorithm) {
	case pqc.MLDSA44, pqc.MLDSA65, pqc.MLDSA87:
		key, err := pqc.GenerateHostMLDSASubjectKey(crypto.CertificateRequestTemplate{
			CommonName: intent.SubjectCommonName, DNSNames: intent.SubjectDNSNames,
		}, crypto.Algorithm(algorithm))
		if err != nil {
			return nil, err
		}
		return &hostRenewSubjectKey{CSRDER: key.CSRDER, privatePEM: key.PrivateKeyPEM, destroy: key.Destroy}, nil
	default:
		return nil, errors.New("relay: requested host subject algorithm is unsupported; no other algorithm was selected")
	}
}
