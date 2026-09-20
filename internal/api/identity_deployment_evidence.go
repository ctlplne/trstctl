// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

type identityDeploymentEvidenceResponse struct {
	IdentityID  string                     `json:"identity_id"`
	ReadAt      time.Time                  `json:"read_at"`
	Receipt     *connectorDeliveryResponse `json:"receipt,omitempty"`
	Certificate *certificateResponse       `json:"certificate,omitempty"`
}

// This read reports the last completed deployment for the exact identity, even
// after retirement. It never substitutes another identity's certificate or claims
// that a retained receipt proves what the listener serves now.
func (a *API) getIdentityDeploymentEvidence(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	identity, err := a.store.GetIdentity(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	out := identityDeploymentEvidenceResponse{IdentityID: identity.ID}
	if identity.Kind == store.KindX509Certificate || string(identity.Kind) == "x509" {
		receipt, found, err := a.store.LatestIdentityDeploymentReceipt(r.Context(), tenantID, identity.ID)
		if err != nil {
			a.writeError(w, err)
			return
		}
		if found {
			value := toConnectorDeliveryResponse(receipt)
			out.Receipt = &value
			certificate, err := a.store.GetCertificateByFingerprint(r.Context(), tenantID, receipt.Fingerprint)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				a.writeError(w, err)
				return
			}
			if err == nil {
				bindings, err := a.store.CertificateIdentityBindings(r.Context(), tenantID, []string{certificate.ID})
				if err != nil {
					a.writeError(w, err)
					return
				}
				value := toCertificateResponse(certificate)
				value.IdentityIDs = bindings[certificate.ID]
				out.Certificate = &value
			}
		}
	}
	out.ReadAt = time.Now().UTC()
	w.Header().Set("Cache-Control", "no-store")
	a.writeJSON(w, http.StatusOK, out)
}
