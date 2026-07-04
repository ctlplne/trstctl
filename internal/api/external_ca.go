// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
)

var (
	ErrExternalCAUnavailable = errors.New("api: external CA registry is not enabled")
	ErrExternalCANotFound    = errors.New("api: external CA not found")
	ErrExternalCAInvalid     = errors.New("api: invalid external CA request")
	ErrExternalCAUpstream    = errors.New("api: external CA upstream failed")
)

// ExternalCAService is the served registry for upstream certificate authorities
// (F4/CLM-03). The server implementation owns the configured CA plugin instances
// and their credentials; the API owns only the tenant-scoped HTTP contract.
type ExternalCAService interface {
	ListExternalCAs(ctx context.Context, tenantID string) ([]ExternalCA, error)
	IssueExternalCA(ctx context.Context, tenantID, id, idempotencyKey string, req ExternalCAIssueRequest) (ExternalCAIssuedCertificate, error)
}

// WithExternalCAs wires the served external-CA registry. When unset, routes fail
// closed with 503 so an upgrade does not silently expose issuance.
func WithExternalCAs(svc ExternalCAService) Option {
	return func(c *config) { c.externalCAs = svc }
}

type ExternalCA struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type ExternalCAIssueRequest struct {
	CSRDER        []byte
	DNSNames      []string
	TTLSeconds    int64
	ProfileName   string
	RequestedEKUs []string
}

type externalCAIssueJSON struct {
	CSRPem        string   `json:"csr_pem"`
	DNSNames      []string `json:"dns_names"`
	TTLSeconds    int64    `json:"ttl_seconds"`
	ProfileName   string   `json:"profile_name"`
	RequestedEKUs []string `json:"requested_ekus"`
}

type ExternalCAIssuedCertificate struct {
	CertificatePEM string    `json:"certificate_pem"`
	Serial         string    `json:"serial"`
	NotAfter       time.Time `json:"not_after"`
	Issuer         string    `json:"issuer"`
}

func (a *API) listExternalCAs(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.externalCAs == nil {
		a.writeError(w, ErrExternalCAUnavailable)
		return
	}
	items, err := a.externalCAs.ListExternalCAs(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, listResponse{Items: items})
}

//trstctl:mutation
func (a *API) issueExternalCA(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.externalCAs == nil {
			return 0, nil, ErrExternalCAUnavailable
		}
		var req externalCAIssueJSON
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		block, _ := pem.Decode([]byte(req.CSRPem))
		if block == nil || block.Type != "CERTIFICATE REQUEST" {
			return 0, nil, errStatus(http.StatusBadRequest, "csr_pem must contain one CERTIFICATE REQUEST PEM block")
		}
		issued, err := a.externalCAs.IssueExternalCA(ctx, tenantID, id, idempotencyKey, ExternalCAIssueRequest{
			CSRDER:        block.Bytes,
			DNSNames:      req.DNSNames,
			TTLSeconds:    req.TTLSeconds,
			ProfileName:   req.ProfileName,
			RequestedEKUs: req.RequestedEKUs,
		})
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, issued, nil
	})
}

func (a *API) writeExternalCAError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, ErrExternalCAUnavailable):
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "external CA registry is not enabled"))
	case errors.Is(err, ErrExternalCANotFound):
		a.writeProblem(w, problem.New(http.StatusNotFound, strings.TrimPrefix(err.Error(), ErrExternalCANotFound.Error()+": ")))
	case errors.Is(err, ErrExternalCAInvalid):
		a.writeProblem(w, problem.New(http.StatusUnprocessableEntity, strings.TrimPrefix(err.Error(), ErrExternalCAInvalid.Error()+": ")))
	case errors.Is(err, ErrExternalCAUpstream):
		a.writeProblem(w, problem.New(http.StatusBadGateway, strings.TrimPrefix(err.Error(), ErrExternalCAUpstream.Error()+": ")))
	default:
		return false
	}
	return true
}
