// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"errors"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/store"
)

type identityIssuanceResultResponse struct {
	IdentityID     string                            `json:"identity_id"`
	RequestKey     string                            `json:"request_key"`
	State          string                            `json:"state"`
	Certificate    *certificateResponse              `json:"certificate,omitempty"`
	CertificatePEM string                            `json:"certificate_pem,omitempty"` // Public certificates only.
	Delivery       *identityIssuanceDeliveryResponse `json:"delivery,omitempty"`
	Retry          *FirstIssuanceRetryReadiness      `json:"retry,omitempty"`
}

type identityIssuanceDeliveryResponse struct {
	Status   string `json:"status"`
	Attempts int    `json:"attempts"`
}

func (a *API) getIdentityIssuanceResult(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	keys, present := r.URL.Query()["request_key"]
	if !present || len(keys) != 1 || strings.TrimSpace(keys[0]) == "" || len(keys[0]) > 256 {
		a.writeError(w, errStatus(http.StatusBadRequest, "one bounded request_key is required"))
		return
	}
	result, err := a.store.GetIdentityIssuanceResult(r.Context(), tenantID, r.PathValue("id"), keys[0])
	if errors.Is(err, store.ErrIdempotencyConflict) {
		a.writeError(w, errStatus(http.StatusConflict, "the issuance result is ambiguous"))
		return
	}
	if err != nil {
		a.writeError(w, err)
		return
	}
	out := identityIssuanceResultResponse{IdentityID: result.IdentityID, RequestKey: result.RequestKey, State: "unavailable"}
	if delivery := result.Delivery; delivery != nil {
		out.Delivery = &identityIssuanceDeliveryResponse{Status: delivery.Status, Attempts: delivery.Attempts}
		out.State = "pending"
		if delivery.Status == "failed" || delivery.Status == "cancelled" {
			out.State = delivery.Status
		}
		if delivery.Status == "cancelled" {
			out.Retry = &FirstIssuanceRetryReadiness{Reason: "This issuance was canceled after the identity was revoked or retired. It cannot be retried."}
		}
	}
	if cert := result.Certificate; cert != nil {
		if cert.IssuanceEventID == "" || len(cert.CertificateDER) == 0 || len(cert.CertificatePEM) == 0 {
			a.writeError(w, errStatus(http.StatusConflict, "the exact issuance has no retained public certificate result"))
			return
		}
		chain, err := certinfo.ParsePublicPEMChain(cert.CertificatePEM, cert.CertificateDER)
		if err != nil {
			a.writeError(w, errStatus(http.StatusConflict, "the retained public certificate envelope is invalid"))
			return
		}
		info, err := certinfo.Inspect(cert.CertificateDER)
		if err != nil || info.SHA256Fingerprint != cert.Fingerprint || info.SerialNumber != cert.Serial {
			a.writeError(w, errStatus(http.StatusConflict, "the retained certificate identity is inconsistent"))
			return
		}
		metadata := toCertificateResponse(*cert)
		out.State, out.Certificate, out.CertificatePEM = "issued", &metadata, string(chain)
	}
	if result.Delivery != nil && result.Delivery.Status == "failed" && a.firstIssuanceRetry != nil {
		readiness, err := a.firstIssuanceRetry.FirstIssuanceRetryReadiness(r.Context(), tenantID, result.IdentityID, result.RequestKey)
		if err != nil {
			readiness = FirstIssuanceRetryReadiness{Reason: "Recovery evidence could not be checked. Refresh after restoring service health."}
		}
		out.Retry = &readiness
	}
	// Issued means a recorded public result; certificate.status still reports
	// revocation/supersession. This never claims deployment or TLS verification.
	w.Header().Set("Cache-Control", "no-store")
	a.writeJSON(w, http.StatusOK, out)
}
