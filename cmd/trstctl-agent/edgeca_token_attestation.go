// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/pem"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/kms/pkcs11"
)

// tokenCertificateReader is the PKCS#11 session's certificate-object read.
type tokenCertificateReader interface {
	CertificatesByLabel(labels ...string) ([][]byte, error)
}

// readEdgeTokenAttestation reads the token's own attestation of the edge
// key (A175): the certificate objects the operator names, leaf first. The
// leaf must certify exactly the CSR's key, checked here before the chain is
// written, so a host never sends an attestation of some other key.
var readEdgeTokenAttestation = func(opts edgeCAOptions, csrDER []byte) ([][]byte, error) {
	labels := splitEdgeLabels(opts.pkcs11AttestationLabels)
	if len(labels) == 0 {
		return nil, nil
	}
	pin, err := readEdgeSecretFile(opts.pkcs11PINFile, true)
	if err != nil {
		return nil, fmt.Errorf("read PKCS#11 user PIN: %w", err)
	}
	defer secret.Wipe(pin)
	session, err := pkcs11.OpenModuleSession(pkcs11.ModuleConfig{
		ModulePath: opts.pkcs11Module, TokenLabel: opts.pkcs11Token, UserPIN: pin, KeyLabelPrefix: opts.pkcs11KeyLabelPrefix,
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = session.Close() }()
	reader, ok := session.(tokenCertificateReader)
	if !ok {
		return nil, fmt.Errorf("this PKCS#11 build cannot read certificate objects")
	}
	chain, err := reader.CertificatesByLabel(labels...)
	if err != nil {
		return nil, err
	}
	if err := deviceattest.TokenAttestationCertifiesCSR(chain[0], csrDER); err != nil {
		return nil, err
	}
	return chain, nil
}

func splitEdgeLabels(raw string) []string {
	var out []string
	for _, label := range strings.Split(raw, ",") {
		if label = strings.TrimSpace(label); label != "" {
			out = append(out, label)
		}
	}
	return out
}

// writeEdgeTokenAttestation writes the chain as PEM, leaf first.
func writeEdgeTokenAttestation(path string, chain [][]byte) error {
	var out []byte
	for _, der := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return writeEdgePrivateFile(path, out)
}
