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
	_, _, err := crypto.ParsePublicCSRPEMWithInspector([]byte(raw), a.subjectCSRInspector)
	if err != nil {
		return fmt.Errorf("subject_csr_pem: %w", err)
	}
	return nil
}
