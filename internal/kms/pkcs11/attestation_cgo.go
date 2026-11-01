// SPDX-License-Identifier: BUSL-1.1

//go:build cgo

package pkcs11

import (
	"errors"
	"fmt"

	p11 "github.com/miekg/pkcs11"
)

// maxAttestationCertificate bounds one certificate object's value.
const maxAttestationCertificate = 16 << 10

// CertificatesByLabel reads certificate objects by label, in the order given
// (A175): the token's attestation of an edge key and the device certificate
// that issued it, as a token module exposes them (YubiKey's ykcs11 names them
// "X.509 Certificate for PIV Attestation <slot>" and "X.509 Certificate for
// PIV Attestation"). A label the token does not hold is an error, so a host
// never sends a partial chain.
func (s *moduleSession) CertificatesByLabel(labels ...string) ([][]byte, error) {
	if len(labels) == 0 {
		return nil, errors.New("pkcs11: no certificate labels")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("pkcs11: session is closed")
	}
	out := make([][]byte, 0, len(labels))
	for _, label := range labels {
		template := []*p11.Attribute{
			p11.NewAttribute(p11.CKA_CLASS, p11.CKO_CERTIFICATE),
			p11.NewAttribute(p11.CKA_LABEL, label),
		}
		if err := s.ctx.FindObjectsInit(s.session, template); err != nil {
			return nil, fmt.Errorf("pkcs11: find certificate %q: %w", label, err)
		}
		objects, _, err := s.ctx.FindObjects(s.session, 2)
		finalErr := s.ctx.FindObjectsFinal(s.session)
		if err != nil {
			return nil, fmt.Errorf("pkcs11: find certificate %q: %w", label, err)
		}
		if finalErr != nil {
			return nil, fmt.Errorf("pkcs11: finish finding certificate %q: %w", label, finalErr)
		}
		switch len(objects) {
		case 0:
			return nil, fmt.Errorf("pkcs11: the token holds no certificate labeled %q", label)
		case 1:
		default:
			return nil, fmt.Errorf("pkcs11: the token holds more than one certificate labeled %q", label)
		}
		attrs, err := s.ctx.GetAttributeValue(s.session, objects[0], []*p11.Attribute{p11.NewAttribute(p11.CKA_VALUE, nil)})
		if err != nil || len(attrs) != 1 || len(attrs[0].Value) == 0 || len(attrs[0].Value) > maxAttestationCertificate {
			return nil, fmt.Errorf("pkcs11: read certificate %q: %v", label, err)
		}
		out = append(out, append([]byte(nil), attrs[0].Value...))
	}
	return out, nil
}
