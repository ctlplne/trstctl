// SPDX-License-Identifier: BUSL-1.1

package pqc

import (
	"encoding/pem"
	"errors"
	"strings"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// HostMLDSASubjectKey keeps the usable subject key at the host executor across
// CSR issuance and installation. The control plane receives only CSRDER.
// Destroy must run on every exit path; exported PEM copies must also be wiped.
type HostMLDSASubjectKey struct {
	CSRDER       []byte
	PublicKeyDER []byte
	private      *secret.Buffer
}

func GenerateHostMLDSASubjectKey(tmpl boundarycrypto.CertificateRequestTemplate, algorithm boundarycrypto.Algorithm) (*HostMLDSASubjectKey, error) {
	if algorithm != MLDSA44 && algorithm != MLDSA65 && algorithm != MLDSA87 {
		return nil, errors.New("pqc: host subject requires an explicit ML-DSA algorithm")
	}
	if strings.TrimSpace(tmpl.CommonName) == "" && len(tmpl.DNSNames) == 0 && len(tmpl.IPAddresses) == 0 && len(tmpl.EmailAddresses) == 0 && len(tmpl.URIs) == 0 {
		return nil, boundarycrypto.ErrNoSubjectNames
	}
	signer, pkcs8, err := GenerateInteroperableMLDSAKey(algorithm)
	if err != nil {
		return nil, err
	}
	defer signer.Destroy()
	private, err := secret.NewFrom(pkcs8)
	secret.Wipe(pkcs8)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			private.Destroy()
		}
	}()
	csr, err := boundarycrypto.CreateOpaqueCertificateRequest(tmpl, mldsaOID(algorithm), signer)
	if err != nil {
		return nil, err
	}
	info, recognized, err := ParsePureMLDSACSR(csr)
	if err != nil {
		return nil, err
	}
	if !recognized || info.KeyAlgorithm != string(algorithm) {
		return nil, errors.New("pqc: generated host request does not match selected algorithm")
	}
	spki, err := boundarycrypto.MarshalOpaqueSubjectPublicKeyInfo(mldsaOID(algorithm), signer.Public().DER)
	if err != nil {
		return nil, err
	}
	success = true
	return &HostMLDSASubjectKey{CSRDER: csr, PublicKeyDER: spki, private: private}, nil
}

func (k *HostMLDSASubjectKey) PrivateKeyPEM() ([]byte, error) {
	if k == nil || k.private == nil {
		return nil, errors.New("pqc: host subject key has been destroyed")
	}
	var exported []byte
	err := k.private.Use(func(pkcs8 []byte) error {
		exported = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return exported, nil
}

func (k *HostMLDSASubjectKey) Destroy() {
	if k == nil {
		return
	}
	if k.private != nil {
		k.private.Destroy()
		k.private = nil
	}
	secret.Wipe(k.CSRDER)
	k.CSRDER = nil
}
