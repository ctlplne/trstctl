package destination

import (
	"context"
	"errors"
	"fmt"
)

// PKCS11 installs a credential as objects on a PKCS#11 token: the certificate
// as a certificate object and, when supplied, the key as a token-resident
// private-key object under hardware custody. The label/id pair ties the two
// objects together so a workload can find the key by the same handle as its
// certificate.
type PKCS11 struct {
	token Token
	label string
	id    []byte
}

var _ Destination = (*PKCS11)(nil)

// NewPKCS11 returns a PKCS#11 destination that stores objects on token under
// the given label and CKA_ID. token is typically a wrapper over a PKCS#11
// module (SoftHSM or a hardware HSM); tests use the in-process software token.
func NewPKCS11(token Token, label string, id []byte) *PKCS11 {
	return &PKCS11{token: token, label: label, id: id}
}

// Install stores the key (if present) and certificate as token objects. The key
// is imported first so the certificate never references an absent key.
func (p *PKCS11) Install(_ context.Context, cred Credential) error {
	if len(cred.CertPEM) == 0 {
		return errors.New("destination: nothing to install (empty certificate)")
	}
	if cred.HasKey() {
		if err := p.token.ImportKey(p.label, p.id, cred.KeyPEM); err != nil {
			return fmt.Errorf("destination: import key into token: %w", err)
		}
	}
	if err := p.token.ImportCertificate(p.label, p.id, cred.CertPEM); err != nil {
		return fmt.Errorf("destination: import certificate into token: %w", err)
	}
	return nil
}

// Describe returns a short identifier for the destination.
func (p *PKCS11) Describe() string { return "pkcs11(" + p.label + ")" }
