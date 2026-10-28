// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/cmdbexport"
)

// CMDBExportBinding describes configured write authority without exposing its
// destination, credential reference or private network configuration.
type CMDBExportBinding struct {
	ID         string `json:"id"`
	Enabled    bool   `json:"enabled"`
	DataSource string `json:"data_source"`
}

type CMDBExportInput struct {
	BindingID     string `json:"binding_id"`
	CertificateID string `json:"certificate_id"`
}

type CMDBExportStatus struct {
	ID            string              `json:"id"`
	BindingID     string              `json:"binding_id"`
	CertificateID string              `json:"certificate_id"`
	Fingerprint   string              `json:"fingerprint"`
	Status        string              `json:"status"`
	Attempts      int                 `json:"attempts"`
	LastError     string              `json:"last_error,omitempty"`
	VerifiedAt    *time.Time          `json:"verified_at,omitempty"`
	Receipt       *cmdbexport.Receipt `json:"receipt,omitempty"`
}

type CMDBCertificateExports interface {
	Bindings(tenantID string) []CMDBExportBinding
	Queue(ctx context.Context, tenantID, key string, input CMDBExportInput) (CMDBExportStatus, error)
	Status(ctx context.Context, tenantID, id string) (CMDBExportStatus, error)
}

var ErrCMDBExportInvalid = errors.New("invalid CMDB certificate export")

func WithCMDBCertificateExports(service CMDBCertificateExports) Option {
	return func(c *config) { c.cmdbExports = service }
}

func (a *API) cmdbCertificateExportRoutes() []route {
	return []route{
		{method: "GET", path: "/api/v1/integrations/cmdb/certificate-export-bindings", opID: "listCMDBCertificateExportBindings", summary: "List this tenant's operator-configured certificate CI write bindings", handler: a.listCMDBExportBindings, resSchema: "CMDBCertificateExportBindingList", successCode: "200", perm: authz.ConnectorsRead},
		{method: "POST", path: "/api/v1/integrations/cmdb/certificate-exports", opID: "createCMDBCertificateExport", summary: "Queue a certificate CI export through a separate operator-owned write binding", handler: a.createCMDBCertificateExport, reqSchema: "CMDBCertificateExportInput", resSchema: "CMDBCertificateExport", successCode: "202", mutation: true, perm: authz.CertsWrite},
		{method: "GET", path: "/api/v1/integrations/cmdb/certificate-exports/{id}", opID: "getCMDBCertificateExport", summary: "Read a certificate export's queue state and independently verified CMDB receipt", handler: a.getCMDBCertificateExport, pathParams: []param{pathUUID("id")}, resSchema: "CMDBCertificateExport", successCode: "200", perm: authz.CertsRead},
	}
}

func (a *API) listCMDBExportBindings(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	items := []CMDBExportBinding{}
	if a.cmdbExports != nil {
		items = a.cmdbExports.Bindings(tenantID)
	}
	a.writeJSON(w, http.StatusOK, struct {
		Items []CMDBExportBinding `json:"items"`
	}{items})
}

//trstctl:mutation
func (a *API) createCMDBCertificateExport(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, key, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.cmdbExports == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "certificate CI export is not configured")
		}
		var input CMDBExportInput
		if err := decodeJSON(r, &input); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		result, err := a.cmdbExports.Queue(ctx, tenantID, key, input)
		if errors.Is(err, ErrCMDBExportInvalid) {
			return 0, nil, errStatus(http.StatusBadRequest, err.Error())
		}
		return http.StatusAccepted, result, err
	})
}

func (a *API) getCMDBCertificateExport(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.cmdbExports == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "certificate CI export is not configured"))
		return
	}
	result, err := a.cmdbExports.Status(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, result)
}
