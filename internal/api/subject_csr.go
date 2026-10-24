// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"context"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
)

// WithSubjectCSRInspector supplies the same proof verifier used by the issuance
// worker. The API retains its bounded, exact PEM envelope validation so runtime
// algorithm support cannot admit extra blocks or skip leading material.
func WithSubjectCSRInspector(inspect func([]byte) (crypto.CSRInfo, error)) Option {
	return func(c *config) { c.subjectCSRInspector = inspect }
}

// validateSubjectCSRPEM admits a requester's CSR before anything is recorded:
// its exact PEM envelope and self-signed proof (epic B1), a key that passes the
// structural weak-key checks, and a key the tenant has not recorded as
// compromised (owner decision, batch 11). Parsing goes through the crypto
// boundary (AN-3). The check is deliberately at the API edge: a bad CSR is a
// caller mistake and belongs in the response to the request that carried it,
// not in a failed outbox delivery minutes later. The issuance worker refuses
// both keys again before signing.
func (a *API) validateSubjectCSRPEM(ctx context.Context, tenantID, raw string) error {
	inspect := a.subjectCSRInspector
	if inspect == nil {
		inspect = crypto.InspectCSR
	}
	der, _, err := crypto.ParsePublicCSRPEMWithInspector([]byte(raw), inspect)
	if err != nil {
		return fmt.Errorf("subject_csr_pem: %w", err)
	}
	inspected, err := crypto.InspectOpaqueCSR(der)
	if err != nil {
		return fmt.Errorf("subject_csr_pem: %w", err)
	}
	if err := crypto.RefuseWeakSubjectKey(inspected.RawSubjectPublicKeyInfo); err != nil {
		return fmt.Errorf("subject_csr_pem: %w", err)
	}
	if err := a.orch.RefuseCompromisedSubjectKey(ctx, tenantID, inspected.RawSubjectPublicKeyInfo); err != nil {
		return fmt.Errorf("subject_csr_pem: %w", err)
	}
	return nil
}

// compromisedKeyGuard refuses a subject key the tenant has recorded as
// compromised, for signers that take a guard (the PKI secrets engine).
func (a *API) compromisedKeyGuard(tenantID string) func(context.Context, []byte) error {
	return func(ctx context.Context, spkiDER []byte) error {
		return a.orch.RefuseCompromisedSubjectKey(ctx, tenantID, spkiDER)
	}
}
