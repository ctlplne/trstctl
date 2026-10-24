// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
)

// WithSubjectCSRInspector supplies the same proof verifier used by the issuance
// worker. The API retains its bounded, exact PEM envelope validation so runtime
// algorithm support cannot admit extra blocks or skip leading material.
func WithSubjectCSRInspector(inspect func([]byte) (crypto.CSRInfo, error)) Option {
	return func(c *config) { c.subjectCSRInspector = inspect }
}

func (a *API) validateSubjectCSRPEM(raw string) error {
	if a.subjectCSRInspector == nil {
		return validateSubjectCSRPEM(raw)
	}
	der, _, err := crypto.ParsePublicCSRPEMWithInspector([]byte(raw), a.subjectCSRInspector)
	if err != nil {
		return fmt.Errorf("subject_csr_pem: %w", err)
	}
	return refuseWeakSubjectCSR(der)
}

// refuseWeakSubjectCSR refuses a CSR whose key fails a structural weak-key
// check before any transition is recorded (owner decision, batch 11), naming
// the check; the issuance worker refuses it again before signing.
func refuseWeakSubjectCSR(der []byte) error {
	inspected, err := crypto.InspectOpaqueCSR(der)
	if err != nil {
		return fmt.Errorf("subject_csr_pem: %w", err)
	}
	if err := crypto.RefuseWeakSubjectKey(inspected.RawSubjectPublicKeyInfo); err != nil {
		return fmt.Errorf("subject_csr_pem: %w", err)
	}
	return nil
}
