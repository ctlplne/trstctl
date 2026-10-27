// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"net/http"

	"trstctl.com/trstctl/internal/assurance"
)

// WithAssurance wires the credential assurance record builder (A179).
func WithAssurance(assembler *assurance.Assembler) Option {
	return func(c *config) { c.assurance = assembler }
}

// getCertificateAssuranceRecord serves one certificate's lifecycle assurance
// record (A179), signed by the isolated audit-evidence signer so it verifies
// offline against the pinned audit JWK set.
func (a *API) getCertificateAssuranceRecord(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.assurance == nil || a.pqcCampaignSigner == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "assurance records are not configured"))
		return
	}
	record, err := a.assurance.Record(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	signed, err := assurance.Sign(a.pqcCampaignSigner, record)
	if err != nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, err.Error()))
		return
	}
	a.writeJSON(w, http.StatusOK, signed)
}
