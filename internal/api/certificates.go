package api

import (
	"context"
	"net/http"
	"time"

	"certctl.io/certctl/internal/crypto/certinfo"
	"certctl.io/certctl/internal/store"
)

type certificateIngestRequest struct {
	PEM                string `json:"pem"`
	OwnerID            string `json:"owner_id"`
	DeploymentLocation string `json:"deployment_location"`
	Source             string `json:"source"`
}

type certificateResponse struct {
	ID                 string     `json:"id"`
	TenantID           string     `json:"tenant_id"`
	OwnerID            *string    `json:"owner_id"`
	Subject            string     `json:"subject"`
	SANs               []string   `json:"sans"`
	Issuer             string     `json:"issuer"`
	Serial             string     `json:"serial"`
	Fingerprint        string     `json:"fingerprint"`
	KeyAlgorithm       string     `json:"key_algorithm"`
	NotBefore          *time.Time `json:"not_before"`
	NotAfter           *time.Time `json:"not_after"`
	DeploymentLocation string     `json:"deployment_location"`
	Source             string     `json:"source"`
	CreatedAt          time.Time  `json:"created_at"`
}

func toCertificateResponse(c store.Certificate) certificateResponse {
	sans := c.SANs
	if sans == nil {
		sans = []string{}
	}
	return certificateResponse{
		ID: c.ID, TenantID: c.TenantID, OwnerID: c.OwnerID, Subject: c.Subject, SANs: sans,
		Issuer: c.Issuer, Serial: c.Serial, Fingerprint: c.Fingerprint, KeyAlgorithm: c.KeyAlgorithm,
		NotBefore: c.NotBefore, NotAfter: c.NotAfter, DeploymentLocation: c.DeploymentLocation,
		Source: c.Source, CreatedAt: c.CreatedAt,
	}
}

func sansOf(info certinfo.Info) []string {
	sans := []string{}
	sans = append(sans, info.DNSNames...)
	sans = append(sans, info.IPAddresses...)
	sans = append(sans, info.EmailAddresses...)
	sans = append(sans, info.URIs...)
	return sans
}

//certctl:mutation
func (a *API) ingestCertificate(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req certificateIngestRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		if req.PEM == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "pem is required")
		}
		info, err := certinfo.Inspect([]byte(req.PEM))
		if err != nil {
			return 0, nil, errStatus(http.StatusUnprocessableEntity, "could not parse certificate: "+err.Error())
		}
		var ownerID *string
		if req.OwnerID != "" {
			if _, err := a.store.GetOwner(ctx, tenantID, req.OwnerID); err != nil {
				if store.IsNotFound(err) {
					return 0, nil, errStatus(http.StatusUnprocessableEntity, "owner_id does not reference an existing owner")
				}
				return 0, nil, err
			}
			ownerID = &req.OwnerID
		}
		source := req.Source
		if source == "" {
			source = "import"
		}
		notBefore, notAfter := info.NotBefore, info.NotAfter
		c, err := a.store.UpsertCertificate(ctx, store.Certificate{
			TenantID: tenantID, OwnerID: ownerID, Subject: info.Subject, SANs: sansOf(info),
			Issuer: info.Issuer, Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint,
			KeyAlgorithm: info.KeyAlgorithm, NotBefore: &notBefore, NotAfter: &notAfter,
			DeploymentLocation: req.DeploymentLocation, Source: source,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toCertificateResponse(c), nil
	})
}

func (a *API) getCertificate(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	c, err := a.store.GetCertificate(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toCertificateResponse(c))
}

func (a *API) listCertificates(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, after, err := a.pageParams(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	var expiringBefore *time.Time
	if s := r.URL.Query().Get("expiring_before"); s != "" {
		ts, perr := time.Parse(time.RFC3339, s)
		if perr != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, "expiring_before must be RFC3339"))
			return
		}
		expiringBefore = &ts
	}
	certs, err := a.store.ListCertificatesPage(r.Context(), tenantID, after, limit, expiringBefore)
	if err != nil {
		a.writeError(w, err)
		return
	}
	items := make([]certificateResponse, 0, len(certs))
	for _, c := range certs {
		items = append(items, toCertificateResponse(c))
	}
	next := ""
	if len(certs) == limit {
		next = encodeCursor(certs[len(certs)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items, NextCursor: next})
}
