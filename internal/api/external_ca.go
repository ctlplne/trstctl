// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
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
	IssueExternalCA(ctx context.Context, tenantID, id, idempotencyKey, requestBinding string, req ExternalCAIssueRequest) (ExternalCAIssuedCertificate, error)
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
	// UpstreamDNS01 is in-process metadata (never serialized): the authority
	// validates names through tenant DNS-01 provider configs, so the endpoint
	// preview must confirm one can publish for the requested name.
	UpstreamDNS01 bool `json:"-"`
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
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	var wire externalCAIssueJSON
	if err := decodeJSON(r, &wire); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	block, rest := pem.Decode([]byte(wire.CSRPem))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		a.writeError(w, errStatus(http.StatusBadRequest, "csr_pem must contain exactly one CERTIFICATE REQUEST PEM block"))
		return
	}
	dnsNames, err := canonicalExternalCAStrings(wire.DNSNames, true)
	if err != nil || len(dnsNames) == 0 {
		a.writeError(w, fmt.Errorf("%w: dns_names must contain at least one non-empty name", ErrExternalCAInvalid))
		return
	}
	requestedEKUs, err := canonicalExternalCAStrings(wire.RequestedEKUs, false)
	if err != nil {
		a.writeError(w, fmt.Errorf("%w: requested_ekus must not contain empty values", ErrExternalCAInvalid))
		return
	}
	if wire.TTLSeconds < 0 {
		a.writeError(w, fmt.Errorf("%w: ttl_seconds cannot be negative", ErrExternalCAInvalid))
		return
	}
	request := ExternalCAIssueRequest{
		CSRDER: append([]byte(nil), block.Bytes...), DNSNames: dnsNames,
		TTLSeconds: wire.TTLSeconds, ProfileName: strings.TrimSpace(wire.ProfileName), RequestedEKUs: requestedEKUs,
	}
	defer secret.Wipe(request.CSRDER)
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding, err := externalCAIssueBinding(principal, id, request)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		// Keep feature availability behind tenant/authentication validation. A
		// direct handler call must not let an unauthenticated caller enumerate
		// whether the external-CA registry is installed.
		if a.externalCAs == nil {
			return 0, nil, ErrExternalCAUnavailable
		}
		issued, err := a.externalCAs.IssueExternalCA(ctx, tenantID, id, idempotencyKey, binding, request)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, issued, nil
	})
}

func canonicalExternalCAStrings(values []string, lower bool) ([]string, error) {
	out := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, errors.New("empty value")
		}
		if lower {
			value = strings.ToLower(value)
		}
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out, nil
}

func externalCAIssueBinding(principal, id string, request ExternalCAIssueRequest) (string, error) {
	canonical := struct {
		Operation     string   `json:"operation"`
		Principal     string   `json:"principal"`
		CAID          string   `json:"ca_id"`
		CSRDER        []byte   `json:"csr_der"`
		DNSNames      []string `json:"dns_names"`
		TTLSeconds    int64    `json:"ttl_seconds"`
		ProfileName   string   `json:"profile_name"`
		RequestedEKUs []string `json:"requested_ekus"`
	}{
		Operation: "external-ca.issue", Principal: principal, CAID: id,
		CSRDER: request.CSRDER, DNSNames: request.DNSNames, TTLSeconds: request.TTLSeconds,
		ProfileName: request.ProfileName, RequestedEKUs: request.RequestedEKUs,
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(encoded)
	return crypto.SHA256Hex(encoded), nil
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
